package com.javatechie.crud.example.controller;

import com.javatechie.crud.example.dto.LoginDTO;
import com.javatechie.crud.example.security.jwt.JWTConfigurer;
import com.javatechie.crud.example.security.jwt.TokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final TokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;

    public AuthController(TokenProvider tokenProvider, AuthenticationManager authenticationManager) {
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
    }

    /**
     * This is the authentication endpoint where an unauthenticated user sends
     * in their username and password and gets back a JWT token.
     *
     *
     * @param loginDTO incoming JSON data
     * @param response http response
     * @return jwt token
     */
    @PostMapping("/authenticate")
    public ResponseEntity<JWTToken> authenticate(@RequestBody LoginDTO loginDTO, @RequestParam(required = false, defaultValue = "false") boolean skipCaptcha, HttpServletRequest request, HttpServletResponse response) {

        try {
            //asks Authentication manager to authenticate this user, which will internally cause
            //VGUserDetailsService to look up user and password, and then authenticationManager will try to match password
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword());
            Authentication authentication = this.authenticationManager.authenticate(authenticationToken);


            log.debug("Authentication successful for {}", loginDTO.getEmail());

            //if got here, authentication was successful, add to Spring Security Context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            //create jwt token
            String jwt = tokenProvider.createToken(authentication);

            //put header with token back in the response and also return as json
            response.addHeader(JWTConfigurer.AUTHORIZATION_HEADER, "Bearer " + jwt);
            JWTToken tokenToReturn = new JWTToken(jwt);

            return ResponseEntity.ok(tokenToReturn);
        } catch (AuthenticationException ae) {
            log.debug("Authentication failed with exception trace", ae); //in debug print stack trace
            throw new RuntimeException(ae.getMessage());
        }
    }

    /**
     * This api is used to renew a user token.
     *
     * Security: Gateway will check for a valid/unexpired token
     */
    static class JWTToken {
        public String token;
        JWTToken(String token) {
            this.token = token;
        }
    }
}
