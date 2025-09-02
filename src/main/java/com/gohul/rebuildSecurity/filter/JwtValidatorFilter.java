package com.gohul.rebuildSecurity.filter;

import com.gohul.rebuildSecurity.constant.MyAppConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class JwtValidatorFilter extends OncePerRequestFilter {

    private final String ORIGINAL_SECRET_KEY= "9fX@w4Zp!r#T7uE2VxC^sPb$yLkQ0hJ1M&Nz8Bd*G3RaUiVoXmCnEt5SjHgYlWqZ6";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader(MyAppConstant.AUTH_HEADER);
        if(token != null && token.startsWith("Bearer "))
        {
            String jotToken = token.substring(7);
            try
            {
                SecretKey decodedKey = Keys.hmacShaKeyFor(ORIGINAL_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
                Claims claims = Jwts.parser()
                        .verifyWith(decodedKey).build()
                        .parseSignedClaims(jotToken).getPayload();
                log.info("Obtained Claims from the user token:: {}", claims);
                String userId = claims.get("USER_ID", String.class);
                String authorities = claims.get("USER_AUTHORITIES", String.class);
                Authentication authentication = new UsernamePasswordAuthenticationToken(userId, null,
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                log.info("Authentication object:: {}",authentication);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            catch (Exception e)
            {
                log.error("Exception raised while verifying the token:: {}", e.getMessage());
                throw new BadCredentialsException("Invalid or expired Jwt token");
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/app/login") || path.equals("/app/public");
    }
}
