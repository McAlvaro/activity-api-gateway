package com.mcalvaro.activityapigateway.auth;

public record LoginResponse(String token, String tokenType, long expiresIn) {
}
