package com.mcalvaro.activityapigateway.security;

import com.mcalvaro.activityapigateway.auth.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private static final String SECRET = "c9a9c25dd7a7cee965c8fd7800db3a1b3f274c365a25814342ddf79738005b64";

    @Test
    void allowsLoginRequestsWithoutAuthorizationHeader() {
        JwtAuthenticationFilter filter = filter(new JwtService(SECRET, 3600));
        AtomicBoolean called = new AtomicBoolean();

        filter.filter(MockServerWebExchange.from(MockServerHttpRequest.post("/api/login").build()),
                exchange -> {
                    called.set(true);
                    return Mono.empty();
                }).block();

        assertThat(called).isTrue();
    }

    @Test
    void rejectsMissingMalformedAndInvalidAuthorizationWithoutCallingChain() {
        JwtAuthenticationFilter filter = filter(new JwtService(SECRET, 3600));
        for (String authorization : new String[]{null, "Basic abc", "Bearer", "Bearer ", "Bearer   ", "Bearer invalid"}) {
            AtomicBoolean called = new AtomicBoolean();
            MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/api/users");
            if (authorization != null) {
                request.header(HttpHeaders.AUTHORIZATION, authorization);
            }
            MockServerWebExchange exchange = protectedExchange(request.build(), "jsonplaceholder-users");

            filter.filter(exchange, ignored -> {
                called.set(true);
                return Mono.empty();
            }).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(called).isFalse();
        }
    }

    @Test
    void removesAuthorizationBeforePassingAuthenticatedRequestUpstream() {
        JwtService jwtService = new JwtService(SECRET, 3600);
        JwtAuthenticationFilter filter = filter(jwtService);
        AtomicReference<String> authorizationSeenByChain = new AtomicReference<>();
        GatewayFilterChain chain = exchange -> {
            authorizationSeenByChain.set(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
            return Mono.empty();
        };

        filter.filter(protectedExchange(MockServerHttpRequest.get("/api/posts")
                        .header(HttpHeaders.AUTHORIZATION, "bEaReR " + jwtService.generateToken("student"))
                        .build(), "jsonplaceholder-posts"), chain)
                .block();

        assertThat(authorizationSeenByChain.get()).isNull();
    }

    @Test
    void rejectsRequestsWithMultipleAuthorizationHeadersWithoutCallingChain() {
        JwtService jwtService = new JwtService(SECRET, 3600);
        AtomicBoolean called = new AtomicBoolean();
        MockServerWebExchange exchange = protectedExchange(MockServerHttpRequest.get("/api/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken("student"))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken("student"))
                .build(), "jsonplaceholder-users");

        filter(jwtService).filter(exchange, ignored -> {
            called.set(true);
            return Mono.empty();
        }).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(called).isFalse();
    }

    @Test
    void rejectsAValidTokenForAnotherSubjectWithoutCallingChain() {
        JwtService jwtService = new JwtService(SECRET, 3600);
        AtomicBoolean called = new AtomicBoolean();
        MockServerWebExchange exchange = protectedExchange(MockServerHttpRequest.get("/api/posts")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken("another-user"))
                .build(), "jsonplaceholder-posts");

        filter(jwtService).filter(exchange, ignored -> {
            called.set(true);
            return Mono.empty();
        }).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(called).isFalse();
    }

    @Test
    void runsBeforeRoutingAtTheSpecifiedOrder() {
        assertThat(filter(new JwtService(SECRET, 3600)).getOrder()).isEqualTo(-100);
    }

    @Test
    void protectsOnlyTheConfiguredRouteIdsRatherThanRequestPath() {
        AtomicBoolean protectedChainCalled = new AtomicBoolean();
        MockServerWebExchange protectedExchange = protectedExchange(
                MockServerHttpRequest.get("/unrelated-path").build(), "jsonplaceholder-users");

        filter(new JwtService(SECRET, 3600)).filter(protectedExchange, ignored -> {
            protectedChainCalled.set(true);
            return Mono.empty();
        }).block();

        AtomicBoolean unprotectedChainCalled = new AtomicBoolean();
        MockServerWebExchange unprotectedExchange = protectedExchange(
                MockServerHttpRequest.get("/api/users").build(), "other-route");
        filter(new JwtService(SECRET, 3600)).filter(unprotectedExchange, ignored -> {
            unprotectedChainCalled.set(true);
            return Mono.empty();
        }).block();

        assertThat(protectedExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(protectedChainCalled).isFalse();
        assertThat(unprotectedChainCalled).isTrue();
    }

    private JwtAuthenticationFilter filter(JwtService jwtService) {
        return new JwtAuthenticationFilter(jwtService, "student");
    }

    private MockServerWebExchange protectedExchange(MockServerHttpRequest request, String routeId) {
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        Route route = mock(Route.class);
        when(route.getId()).thenReturn(routeId);
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, route);
        return exchange;
    }
}
