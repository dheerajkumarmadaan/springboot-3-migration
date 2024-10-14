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
        String secret = "87f4e91555052cdf4ef1cd02f8a0d31c4a165a5a8c10c0e43481df35e2cbea73edd8d4411710c67f6953d230b5bc6235f06a5614b8e8999f023d85b141756c59";
        String ttlSeconds = "60000";

        return new TokenProvider(secret, ttlSeconds);
    }
    @Bean
    public Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint() {
        return new Http401UnauthorizedEntryPoint();
    }
}

