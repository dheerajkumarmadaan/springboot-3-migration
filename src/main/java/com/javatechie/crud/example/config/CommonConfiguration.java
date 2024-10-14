package com.javatechie.crud.example.config;

import com.javatechie.crud.example.security.Http401UnauthorizedEntryPoint;
import com.javatechie.crud.example.security.jwt.TokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Configuration class for specifying beans that is common for all the services.
 * If you are looking to add things to all services but not Gateway, see CommonBlockingConfiguration
 */
public class CommonConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(CommonConfiguration.class);

    @Bean
    public TokenProvider tokenProvider(Environment env) {
        String secret = "secret";
        String ttlSeconds = "60000";

        return new TokenProvider(secret, ttlSeconds);
    }
    @Bean
    public Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint() {
        return new Http401UnauthorizedEntryPoint();
    }
}

