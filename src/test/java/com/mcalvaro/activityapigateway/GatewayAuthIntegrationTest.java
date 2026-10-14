package com.mcalvaro.activityapigateway;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import com.mcalvaro.activityapigateway.auth.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewayAuthIntegrationTest {

    private static final AtomicReference<String> upstreamPath = new AtomicReference<>();
    private static final AtomicReference<String> upstreamQuery = new AtomicReference<>();
    private static final AtomicReference<String> upstreamAuthorization = new AtomicReference<>();
    private static final AtomicInteger upstreamRequests = new AtomicInteger();
    private static final HttpServer upstream = startUpstream();

    @LocalServerPort
    private int port;

    @Autowired
    private JwtService jwtService;

    @DynamicPropertySource
    static void configureUpstream(DynamicPropertyRegistry registry) {
        registry.add("JSONPLACEHOLDER_URL", () -> "http://localhost:" + upstream.getAddress().getPort());
    }

    @AfterAll
    static void stopUpstream() {
        upstream.stop(0);
    }

    @Test
    void rewritesUsersPathPreservesQueryAndDoesNotPropagateAuthorizationOrRedirect() {
        assertSuccessfulProxy("/api/users?limit=1", "/users", "limit=1", login());
    }

    @Test
    void rewritesPostsPathPreservesQueryAndDoesNotPropagateAuthorizationOrRedirect() {
        assertSuccessfulProxy("/api/posts?userId=1", "/posts", "userId=1", login());
    }

    @Test
    void rejectsInvalidCredentialsAndTokensWithoutRedirectingOrCallingUpstream() {
        int requestsBefore = upstreamRequests.get();

        client().post().uri("/api/login")
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .bodyValue("{\"username\":\"student\",\"password\":\"wrong\"}")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist(HttpHeaders.LOCATION);

        client().get().uri("/api/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer invalid")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist(HttpHeaders.LOCATION);

        client().get().uri("/api/posts")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken("another-user"))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist(HttpHeaders.LOCATION);

        assertThat(upstreamRequests.get()).isEqualTo(requestsBefore);
    }

    @Test
    void trailingSlashDoesNotMatchTheExactRouteAndNeverReachesUpstream() {
        int requestsBefore = upstreamRequests.get();

        client().get().uri("/api/users/")
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().doesNotExist(HttpHeaders.LOCATION);

        assertThat(upstreamRequests.get()).isEqualTo(requestsBefore);
    }

    private String login() {
        return client().post().uri("/api/login")
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .bodyValue("{\"username\":\"student\",\"password\":\"gateway123\"}")
                .exchange()
                .expectStatus().isOk()
                .returnResult(String.class)
                .getResponseBody()
                .blockFirst()
                .replaceAll(".*\\\"token\\\":\\\"([^\\\"]+)\\\".*", "$1");
    }

    private void assertSuccessfulProxy(String uri, String expectedPath, String expectedQuery, String token) {
        upstreamPath.set(null);
        upstreamQuery.set(null);
        upstreamAuthorization.set(null);

        client().get().uri(uri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist(HttpHeaders.LOCATION)
                .expectBody().json("[{\"id\":1}]");

        assertThat(upstreamPath.get()).isEqualTo(expectedPath);
        assertThat(upstreamQuery.get()).isEqualTo(expectedQuery);
        assertThat(upstreamAuthorization.get()).isNull();
    }

    private WebTestClient client() {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    private static HttpServer startUpstream() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            server.createContext("/", exchange -> {
                upstreamRequests.incrementAndGet();
                upstreamPath.set(exchange.getRequestURI().getPath());
                upstreamQuery.set(exchange.getRequestURI().getQuery());
                upstreamAuthorization.set(exchange.getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION));
                byte[] body = "[{\"id\":1}]".getBytes();
                exchange.getResponseHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();
            return server;
        } catch (IOException exception) {
            throw new IllegalStateException("Could not start local upstream", exception);
        }
    }
}
