package com.mcalvaro.activityapigateway.auth;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final String configuredUsername;
    private final String configuredPassword;
    private final JwtService jwtService;

    public AuthController(
            @Value("${app.auth.username}") String configuredUsername,
            @Value("${app.auth.password}") String configuredPassword,
            JwtService jwtService) {
        this.configuredUsername = configuredUsername;
        this.configuredPassword = configuredPassword;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        if (!credentialsMatch(request)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok(new LoginResponse(
                jwtService.generateToken(request.username()),
                "Bearer",
                jwtService.getExpirationSeconds()));
    }

    private boolean credentialsMatch(LoginRequest request) {
        return MessageDigest.isEqual(
                configuredUsername.getBytes(StandardCharsets.UTF_8),
                request.username().getBytes(StandardCharsets.UTF_8))
                && MessageDigest.isEqual(
                        configuredPassword.getBytes(StandardCharsets.UTF_8),
                        request.password().getBytes(StandardCharsets.UTF_8));
    }
}
