package com.mcalvaro.activityapigateway.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class JwtServiceTest {

    private static final String SECRET = "c9a9c25dd7a7cee965c8fd7800db3a1b3f274c365a25814342ddf79738005b64";

    @Test
    void generatesHs256TokenWithSubjectIssuedAtExpirationAndConfiguredTtlFromInjectedClock() {
        Instant issuedAt = Instant.parse("2030-10-14T00:00:00Z");
        JwtService service = new JwtService(SECRET, 3600, Clock.fixed(issuedAt, ZoneOffset.UTC));

        String token = service.generateToken("student");

        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(hexToBytes(SECRET)))
                .build()
                .parseSignedClaims(token)
                .getPayload();
        assertThat(token.split("\\.")[0]).isEqualTo("eyJhbGciOiJIUzI1NiJ9");
        assertThat(claims.getSubject()).isEqualTo("student");
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull();
        assertThat(Duration.between(claims.getIssuedAt().toInstant(), claims.getExpiration().toInstant()).toSeconds())
                .isEqualTo(3600);
        assertThat(claims.getIssuedAt().toInstant()).isEqualTo(issuedAt);
    }

    @Test
    void rejectsTokenWithInvalidSignature() {
        JwtService issuer = new JwtService(SECRET, 3600);
        JwtService validator = new JwtService("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 3600);

        assertThat(validator.validateAndGetSubject(issuer.generateToken("student"))).isEmpty();
    }

    @Test
    void rejectsExpiredToken() {
        JwtService service = new JwtService(SECRET, 3600);
        String expiredToken = Jwts.builder()
                .subject("student")
                .issuedAt(Date.from(Instant.now().minusSeconds(120)))
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(Keys.hmacShaKeyFor(hexToBytes(SECRET)), Jwts.SIG.HS256)
                .compact();

        assertThat(service.validateAndGetSubject(expiredToken)).isEmpty();
    }

    @Test
    void rejectsTokensSignedWithAnAlgorithmOtherThanHs256() throws Exception {
        JwtService service = new JwtService(SECRET, 3600);
        String token = hs384Token("student");

        assertThat(service.validateAndGetSubject(token)).isEmpty();
    }

    @Test
    void returnsTheValidatedTokenSubject() {
        JwtService service = new JwtService(SECRET, 3600);

        assertThat(service.validateAndGetSubject(service.generateToken("student"))).contains("student");
    }

    @Test
    void rejectsHs256TokensWithoutUsableSubject() {
        JwtService service = new JwtService(SECRET, 3600);
        String tokenWithoutSubject = Jwts.builder()
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(Keys.hmacShaKeyFor(hexToBytes(SECRET)), Jwts.SIG.HS256)
                .compact();
        String tokenWithBlankSubject = Jwts.builder()
                .subject(" ")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(Keys.hmacShaKeyFor(hexToBytes(SECRET)), Jwts.SIG.HS256)
                .compact();

        assertThat(service.validateAndGetSubject(tokenWithoutSubject)).isEmpty();
        assertThat(service.validateAndGetSubject(tokenWithBlankSubject)).isEmpty();
    }

    @Test
    void rejectsMalformedAndWrongLengthSecretsAndNonPositiveTtl() {
        assertThatIllegalArgumentException().isThrownBy(() -> new JwtService("not-hex", 3600));
        assertThatIllegalArgumentException().isThrownBy(() -> new JwtService("aa".repeat(31), 3600));
        assertThatIllegalArgumentException().isThrownBy(() -> new JwtService("aa".repeat(33), 3600));
        assertThatIllegalArgumentException().isThrownBy(() -> new JwtService(SECRET, 0));
        assertThatIllegalArgumentException().isThrownBy(() -> new JwtService(SECRET, -1));
    }

    private static byte[] hexToBytes(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }

    private static String hs384Token(String subject) throws Exception {
        String header = base64Url("{\"alg\":\"HS384\"}");
        String payload = base64Url("{\"sub\":\"" + subject + "\",\"iat\":1791936000,\"exp\":1791939600}");
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(new SecretKeySpec(hexToBytes(SECRET), "HmacSHA384"));
        return header + "." + payload + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal((header + "." + payload).getBytes(StandardCharsets.US_ASCII)));
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.US_ASCII));
    }
}
