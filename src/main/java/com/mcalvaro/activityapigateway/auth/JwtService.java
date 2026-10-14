package com.mcalvaro.activityapigateway.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.Optional;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long expirationSeconds;
    private final Clock clock;

    @Autowired
    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.expiration-seconds}") long expirationSeconds,
            Clock clock) {
        byte[] secretBytes = decodeSecret(secret);
        if (expirationSeconds <= 0) {
            throw new IllegalArgumentException("JWT expiration must be positive");
        }
        this.signingKey = Keys.hmacShaKeyFor(secretBytes);
        this.expirationSeconds = expirationSeconds;
        this.clock = clock;
    }

    public JwtService(String secret, long expirationSeconds) {
        this(secret, expirationSeconds, Clock.systemUTC());
    }

    public String generateToken(String username) {
        Instant issuedAt = clock.instant();
        return Jwts.builder()
                .subject(username)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(issuedAt.plusSeconds(expirationSeconds)))
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    public Optional<String> validateAndGetSubject(String token) {
        try {
            Jws<Claims> signedClaims = Jwts.parser()
                    .verifyWith(signingKey)
                    .sig().add(Jwts.SIG.HS256).and()
                    .build()
                    .parseSignedClaims(token);
            if (!Jwts.SIG.HS256.getId().equals(signedClaims.getHeader().getAlgorithm())) {
                return Optional.empty();
            }
            return Optional.ofNullable(signedClaims.getPayload().getSubject())
                    .filter(subject -> !subject.isBlank());
        } catch (RuntimeException exception) {
            return Optional.empty();
        }
    }

    public long getExpirationSeconds() {
        return expirationSeconds;
    }

    private static byte[] decodeSecret(String secret) {
        try {
            byte[] secretBytes = HexFormat.of().parseHex(secret);
            if (secretBytes.length != 32) {
                throw new IllegalArgumentException("JWT secret must decode to exactly 32 bytes");
            }
            return secretBytes;
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("JWT secret must be a 32-byte hexadecimal value", exception);
        }
    }
}
