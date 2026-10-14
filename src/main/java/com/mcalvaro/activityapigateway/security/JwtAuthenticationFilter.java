package com.mcalvaro.activityapigateway.security;

import com.mcalvaro.activityapigateway.auth.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final String BEARER_SCHEME = "Bearer";
    private static final Set<String> PROTECTED_ROUTE_IDS = Set.of(
            "jsonplaceholder-users",
            "jsonplaceholder-posts"
    );

    private final JwtService jwtService;
    private final String configuredUsername;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            @Value("${app.auth.username}") String configuredUsername
    ) {
        this.jwtService = jwtService;
        this.configuredUsername = configuredUsername;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!isProtectedRoute(exchange)) {
            return chain.filter(exchange);
        }

        Optional<String> subject = validatedSubject(exchange.getRequest());
        if (subject.filter(configuredUsername::equals).isEmpty()) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        ServerHttpRequest sanitizedRequest = exchange.getRequest().mutate()
                .headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION))
                .build();
        return chain.filter(exchange.mutate().request(sanitizedRequest).build());
    }

    @Override
    public int getOrder() {
        return -100;
    }

    private boolean isProtectedRoute(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        return route != null && PROTECTED_ROUTE_IDS.contains(route.getId());
    }

    private Optional<String> validatedSubject(ServerHttpRequest request) {
        List<String> authorizationHeaders = request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION);
        if (authorizationHeaders.size() != 1) {
            return Optional.empty();
        }

        String authorization = authorizationHeaders.getFirst();
        int separator = authorization.indexOf(' ');
        if (separator <= 0 || separator == authorization.length() - 1
                || !BEARER_SCHEME.equalsIgnoreCase(authorization.substring(0, separator))) {
            return Optional.empty();
        }

        String token = authorization.substring(separator + 1).strip();
        return token.isEmpty() ? Optional.empty() : jwtService.validateAndGetSubject(token);
    }
}
