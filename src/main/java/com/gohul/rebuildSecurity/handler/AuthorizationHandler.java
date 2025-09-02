package com.gohul.rebuildSecurity.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.time.LocalDateTime;

@Slf4j
public class AuthorizationHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

        String errMsg = (accessDeniedException != null && accessDeniedException.getMessage() != null) ? accessDeniedException.getMessage() : "UnAuthorized";
        log.error("Authorization Failed due to {}", errMsg);
        String path = request.getRequestURI();
        LocalDateTime dateTime = LocalDateTime.now();
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setHeader("custom-authorized-serror", "failed due to unauthorised");
        response.setContentType("application/json;charset=UTF-8");
        String errResBody = String.format("{\"timestamp\": \"%s\", \"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                dateTime, HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase(),
                errMsg, path);
        response.getWriter().write(errResBody);
    }
}
