package com.javatechie.crud.example.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.javatechie.crud.example.security.TTNSpringUserDetails;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;

/**
 * This class is in charge of creating, validating and parsing JWT tokens
 */
public class TokenProvider {

    private static final String USER_ID_KEY = "user";
    private static final String USER_EMAIL_KEY = "email";

    private String secretKey;
    private long tokenValidityInMilliseconds; //how long token is valid

    //object mapper for parsing jwt custom fields
    ObjectMapper objectMapper = new ObjectMapper();

    private final Logger log = LoggerFactory.getLogger(TokenProvider.class);

    public TokenProvider(String secretKey, String tokenValidityInSeconds) {
        this.secretKey = secretKey;
        this.tokenValidityInMilliseconds = 1000 * Long.parseLong(tokenValidityInSeconds);
    }

    public String createToken(Authentication authentication) {
        long durationMillis = this.tokenValidityInMilliseconds;
        return createToken(((TTNSpringUserDetails)authentication.getPrincipal()).getUserId(), authentication.getName(), durationMillis);
    }

    public String createToken(UUID userId, String username) {
        long durationMillis = this.tokenValidityInMilliseconds;
        return createToken(userId, username, durationMillis);
    }

    //For use with service to service token generation
    public String createToken(UUID userId, String username, long durationMillis) {
        long now = (new Date()).getTime();
        Date validity = new Date(now + durationMillis);
            String token = Jwts.builder()
                .setSubject(username)
                .claim(USER_ID_KEY, userId)
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .setExpiration(validity)
                .compact();

            return token;
    }

    /**
     * Parses the current user object out of the jwt token and into an Authentication object that can later be stored in the SpringSecurityContext
     * @param jwtToken the jwt token
     * @return Authentication object
     */
    public Authentication getAuthentication(String jwtToken) {
        Claims claims = getClaimsFromJwt(jwtToken);

        Collection<GrantedAuthority> authorities = new ArrayList<>();

        UUID userId = getUUIDFromClaims(claims);
        TTNSpringUserDetails principal = new TTNSpringUserDetails(claims.getSubject(), "", authorities, userId);

        return new UsernamePasswordAuthenticationToken(principal, jwtToken, authorities);
    }

    public UUID getUUIDFromJwt(String jwtToken){
        return getUUIDFromClaims(getClaimsFromJwt(jwtToken));
    }

    public Date getExpirationFromJwt(String jwtToken) {
        return getClaimsFromJwt(jwtToken).getExpiration();
    }

    private UUID getUUIDFromClaims(Claims claims) {
        return UUID.fromString(claims.get(USER_ID_KEY).toString());
    }

    private Claims getClaimsFromJwt(String jwtToken) {
        return Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(jwtToken)
            .getBody();
    }

    /**
     * Validates the jwt token for bad signature, expired token, etc...
     * @param jwtToken the jwt token
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String jwtToken) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return true;
        } catch (SignatureException e) {
            log.info("Invalid JWT signature.");
            log.trace("Invalid JWT signature trace: {}", jwtToken, e);
        } catch (MalformedJwtException e) {
            log.info("Invalid JWT token.");
            log.trace("Invalid JWT token trace: {}", jwtToken, e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token: {}", e.getMessage());
            log.trace("Expired JWT token trace: {}", jwtToken, e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            log.trace("Unsupported JWT token trace: {}", jwtToken, e);
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            log.trace("JWT token compact of handler are invalid trace: {}", jwtToken, e);
        }
        return false;
    }
}
