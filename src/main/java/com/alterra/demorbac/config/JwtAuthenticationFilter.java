package com.alterra.demorbac.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.alterra.demorbac.component.TokenProvider;
import com.alterra.demorbac.constant.Constant;
import com.alterra.demorbac.model.User;
import com.alterra.demorbac.service.UserService;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthenticationFilter extends GenericFilterBean {

    
    private final UserService userService;
    private final TokenProvider jwtTokenUtil;

    public JwtAuthenticationFilter(TokenProvider jwtTokenUtil, UserService userService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.userService = userService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String authorization = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        String token = null;
        String username = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authorization != null && authorization.startsWith(Constant.General.BEARER)) {
            token = authorization.replace(Constant.General.BEARER, "");

            try {
                username = jwtTokenUtil.getUsername(token);
            } catch (IllegalArgumentException e) {
                log.error("An error occured during getting username from token", e);
            } catch (ExpiredJwtException e) {
                log.error("Token is expired", e);
            } catch (SignatureException e) {
                log.error("Authentication Failed. Username or Password not valid.");
            }
        }

        if (username != null && authentication == null) {
            User user = (User) userService.loadUserByUsername(username);

            if (jwtTokenUtil.isTokenValid(token, user)) {
                Authentication authenticationToken = jwtTokenUtil.getAuthenticationToken(token, authentication, user);

                log.debug("Authenticated user: {}, setting security context", username);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        chain.doFilter(request, response);
        
    }
    
}
