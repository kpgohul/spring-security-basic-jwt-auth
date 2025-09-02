package com.gohul.rebuildSecurity.filter;

import com.gohul.rebuildSecurity.constant.MyAppConstant;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
public class JwtGeneratorFilter extends OncePerRequestFilter {

//    @Value("${jwt.secret}")
    private final String ORIGINAL_SECRET_KEY= "9fX@w4Zp!r#T7uE2VxC^sPb$yLkQ0hJ1M&Nz8Bd*G3RaUiVoXmCnEt5SjHgYlWqZ6";

//    @Value("${jwt.expiration}")
    private final Long TIMEOUT = 86400000L;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null)
        {
            SecretKey decodedKey = Keys.hmacShaKeyFor(ORIGINAL_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder()
                    .issuer("GohulSecurityApplication")
                    .claim("USER_ID", authentication.getName())
                    .claim("USER_AUTHORITIES", authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(",")))
                    .issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + TIMEOUT))
                    .signWith(decodedKey)
                    .compact();

            log.info("Generated new JWT token for the current user:: {}", jwt.toString());
            response.setHeader(MyAppConstant.AUTH_HEADER, "Bearer "+jwt);
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().equals("/app/login") ||
                request.getRequestURI().equals("/app/public");
    }


}
