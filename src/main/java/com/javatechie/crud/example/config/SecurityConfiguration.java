package com.javatechie.crud.example.config;

import com.javatechie.crud.example.security.Http401UnauthorizedEntryPoint;
import com.javatechie.crud.example.security.jwt.JWTConfigurer;
import com.javatechie.crud.example.security.jwt.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * This class configures all the endpoint security for the application, specifying which endpoints require security.
 * FYI, a lot of code taken from JHipster
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private TokenProvider tokenProvider;

    // Taken from below link during migration from 2.0.0.M3 to 2.o.o.release
    // https://stackoverflow.com/questions/21633555/how-to-inject-authenticationmanager-using-java-configuration-in-a-custom-filter?answertab=active#tab-top
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .cors() //enable cors, by default looks for a corsConfigurationSource bean, defined below
        .and()
            .exceptionHandling().authenticationEntryPoint(http401UnauthorizedEntryPoint) //return 401 if unauthenticated, so UI can show login
        .and()
            .csrf().disable()                   //disable csrf since no session
            .headers().frameOptions().disable() //modify this if need to disallow iFraming in other apps (no UIs yet)
        .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //NO SESSIONS
        .and()
            // note, all permitAll controller methods that are creating/modifying database entities should be logged in as anonymous user. See securityService.logInAnonymousUser()
            .authorizeRequests()
                //allow authentication endpoint where user gives username/password and gets a token back
                .antMatchers("/auth/authenticate").permitAll()
                //NOTE if making endpoints permitAll(), also need to do it security config of odyssey-gateway or else it will block unauthenticated requests

                //securing the Spring Boot management endpoints (including in proxied services) so only developers can view
                .antMatchers("/**/application/health").permitAll() //healthcheck endpoint is public
                .antMatchers("/**/application/info").permitAll() //info endpoint is public

                .antMatchers("/**").authenticated() //IMPORTANT: require authentication for all other calls, must be below exclusions
        .and()
            .apply(new JWTConfigurer(tokenProvider)); //configures JWTFilter

    }

    //NOTE: not setting up CORS for dev profile, since this is done in odyssey-gateway,
    // and if have it here, we end up with 2 CORS headers, which prevents CORS from working.
}
