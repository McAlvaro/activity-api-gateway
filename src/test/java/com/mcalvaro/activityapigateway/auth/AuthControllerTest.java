package com.mcalvaro.activityapigateway.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

class AuthControllerTest {

    private WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToController(new AuthController(
                "student", "gateway123", new JwtService(
                "c9a9c25dd7a7cee965c8fd7800db3a1b3f274c365a25814342ddf79738005b64", 3600)))
                .build();
    }

    @Test
    void returnsJwtResponseForValidCredentials() {
        client.post().uri("/api/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"student\",\"password\":\"gateway123\"}")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist(HttpHeaders.LOCATION)
                .expectBody()
                .jsonPath("$.token").isNotEmpty()
                .jsonPath("$.tokenType").isEqualTo("Bearer")
                .jsonPath("$.expiresIn").isEqualTo(3600);
    }

    @Test
    void returnsBadRequestForMissingCredentials() {
        client.post().uri("/api/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectHeader().doesNotExist(HttpHeaders.LOCATION);
    }

    @Test
    void returnsUnauthorizedWithoutRedirectForIncorrectCredentials() {
        client.post().uri("/api/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"student\",\"password\":\"wrong\"}")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist(HttpHeaders.LOCATION);
    }
}
