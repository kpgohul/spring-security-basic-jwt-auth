package com.gohul.rebuildSecurity.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.Instant;

@Slf4j
public class AuthenticationHandler implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        String message = (authException != null && authException.getMessage() != null)? authException.getMessage() : "Authentication Failed!";
        log.error("Authentication Failed due to {}",message);
        String path = request.getRequestURI();
        Instant now = Instant.now();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader("X-Failed-Reason", "Authentication Failed!");
        response.setContentType(MediaType.APPLICATION_JSON.toString());
        String errResBody = String.format("{\"timestamp\": \"%s\", \"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                now, HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase(),
                message, path);
        response.getWriter().write(errResBody);
    }
}
