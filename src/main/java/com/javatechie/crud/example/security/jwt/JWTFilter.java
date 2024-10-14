package com.javatechie.crud.example.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Filters incoming requests and installs a Spring Security principal if a header corresponding to a valid user is
 * found.
 */
public class JWTFilter extends GenericFilterBean {

    private TokenProvider tokenProvider;

    public JWTFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * If the incoming request has a JWT token, then extract the Authentication information
     * from it and put it in the Spring Security Context
     * @param servletRequest the request
     * @param servletResponse the response
     * @param filterChain filterChain to continue
     * @throws IOException up
     * @throws ServletException up
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
        throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String jwt = resolveToken(httpServletRequest);
        if (StringUtils.hasText(jwt) && this.tokenProvider.validateToken(jwt)) {
            Authentication authentication = this.tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    /**
     * @param request the request
     * @return parsed Bearer token from Authorization header
     */
    public static String resolveToken(HttpServletRequest request){
        String authHeaderValue = request.getHeader(JWTConfigurer.AUTHORIZATION_HEADER);
        return JWTUtil.resolveTokenFromAuthHeader(authHeaderValue);
    }
}
