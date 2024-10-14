package com.javatechie.crud.example.config;

import com.javatechie.crud.example.security.Http401UnauthorizedEntryPoint;
import com.javatechie.crud.example.security.jwt.JWTConfigurer;
import com.javatechie.crud.example.security.jwt.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * This class configures all the endpoint security for the application, specifying which endpoints require security.
 * FYI, a lot of code taken from JHipster
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration  {

    @Autowired
    private TokenProvider tokenProvider;

    // Taken from below link during migration from 2.0.0.M3 to 2.o.o.release
    // https://stackoverflow.com/questions/21633555/how-to-inject-authenticationmanager-using-java-configuration-in-a-custom-filter?answertab=active#tab-top
    /*~~(Migrate manually based on https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)~~>*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Autowired
    Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .exceptionHandling(handling -> handling.authenticationEntryPoint(http401UnauthorizedEntryPoint))
                .csrf(csrf -> csrf.disable())                   //disable csrf since no session
                .headers(headers -> headers.frameOptions(options -> options.disable()))
                .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // note, all permitAll controller methods that are creating/modifying database entities should be logged in as anonymous user. See securityService.logInAnonymousUser()
                .authorizeHttpRequests(requests -> requests
                        //allow authentication endpoint where user gives username/password and gets a token back
                        .requestMatchers("/auth/authenticate").permitAll()
                        //NOTE if making endpoints permitAll(), also need to do it security config of odyssey-gateway or else it will block unauthenticated requests

                        //securing the Spring Boot management endpoints (including in proxied services) so only developers can view
                        .requestMatchers("/application/health").permitAll() //healthcheck endpoint is public
                        .requestMatchers("/application/info").permitAll() //info endpoint is public

                        .requestMatchers("/**").authenticated())
                .with(new JWTConfigurer(tokenProvider), withDefaults());
              return http.build();
    }

    //NOTE: not setting up CORS for dev profile, since this is done in odyssey-gateway,
    // and if have it here, we end up with 2 CORS headers, which prevents CORS from working.
}
