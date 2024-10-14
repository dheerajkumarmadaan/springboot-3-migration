package com.javatechie.crud.example.security.jwt;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;

public class JWTUtil {

    public static String resolveTokenWebflux(ServerHttpRequest request) {
        String authHeaderValue = request.getHeaders().getFirst(JWTConfigurer.AUTHORIZATION_HEADER);
        return JWTUtil.resolveTokenFromAuthHeader(authHeaderValue);
    }

    public static String resolveTokenFromAuthHeader(String authHeaderValue) {
        //authorization header has text, starts with "Bearer ey"  - "ey" is base64 for "{" which means its base64 encoded json
        if (StringUtils.hasText(authHeaderValue) && authHeaderValue.startsWith("Bearer ey")) {
            return authHeaderValue.substring(7);
        }
        return null;
    }
}
