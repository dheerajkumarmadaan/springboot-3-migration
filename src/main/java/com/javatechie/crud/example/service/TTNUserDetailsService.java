package com.javatechie.crud.example.service;

import com.javatechie.crud.example.security.TTNSpringUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Extends UserDetailsService so that it can be plugged into Spring Security for loading up a user security context by their name
 */
@Component("userDetailsService")
public class TTNUserDetailsService implements UserDetailsService {

    private final Logger log = LoggerFactory.getLogger(TTNUserDetailsService.class);

    public TTNUserDetailsService(PasswordEncoder passwordEncoder) {
    }

    @Override
    public TTNSpringUserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.debug("Authenticating {}", email);

        List<GrantedAuthority> authorities = new ArrayList<>();
        String passwordEncoded = new BCryptPasswordEncoder().encode("test");
        return new TTNSpringUserDetails(email, passwordEncoded, authorities, UUID.randomUUID());
    }
}
