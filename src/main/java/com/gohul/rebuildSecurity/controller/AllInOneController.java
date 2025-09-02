package com.gohul.rebuildSecurity.controller;

import com.fasterxml.jackson.databind.ser.std.RawSerializer;
import com.gohul.rebuildSecurity.constant.MyAppConstant;
import com.gohul.rebuildSecurity.dto.LoginRequestDto;
import com.gohul.rebuildSecurity.dto.LoginResponseDto;
import com.gohul.rebuildSecurity.dto.UserDto;
import com.gohul.rebuildSecurity.entity.Role;
import com.gohul.rebuildSecurity.entity.User;
import com.gohul.rebuildSecurity.entity.UserRoleMapping;
import com.gohul.rebuildSecurity.repo.RoleRepo;
import com.gohul.rebuildSecurity.repo.UserRepo;
import com.gohul.rebuildSecurity.repo.UserRoleRepo;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import javax.security.auth.login.AccountNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/app")
@Validated
@RequiredArgsConstructor
@Slf4j
public class AllInOneController {

    private final UserRepo userRepo;
    private final PasswordEncoder encoder;
    private final UserRoleRepo userRoleRepo;
    private final RoleRepo roleRepo;
    private final AuthenticationManager authenticationManager;

    //    @Value("${jwt.secret}")
    private final String ORIGINAL_SECRET_KEY= "9fX@w4Zp!r#T7uE2VxC^sPb$yLkQ0hJ1M&Nz8Bd*G3RaUiVoXmCnEt5SjHgYlWqZ6";
    //    @Value("${jwt.expiration}")
    private Long TIMEOUT = 86400000L;


    @PostMapping("/sign-up")
    public ResponseEntity<?> signUp(@RequestBody UserDto dto) {
        String hashedPwd = encoder.encode(dto.getPassword());
        User user = User.builder()
                .username(dto.getUsername())
                .email(dto.getPassword())
                .password(hashedPwd)
                .build();
        Role role = roleRepo.findByRole("USER")
                .orElseThrow(() -> new RuntimeException("Role:: USER is not found!"));
        User savedUser = userRepo.save(user);
        UserRoleMapping map = userRoleRepo.save(UserRoleMapping.builder()
                .userId(savedUser.getId())
                .roleId(role.getId())
                .build());
        if (savedUser.getId() > 0 && map.getId() > 0)
            return ResponseEntity.status(HttpStatus.CREATED).body("Account created successfully!");
        throw new RuntimeException("Account creation failed!");
    }

    @PostMapping("/sign-in")
    public ResponseEntity<?> signIn(@RequestBody LoginRequestDto dto)
    {
        log.info("Trying to log-in");
        String jwt = null;
        try {
            Authentication authBefore = UsernamePasswordAuthenticationToken.unauthenticated(dto.getValue(), dto.getPassword());
            Authentication authAfter = authenticationManager.authenticate(authBefore);
            if (authAfter != null && authAfter.isAuthenticated()) {
                SecretKey decodedKey = Keys.hmacShaKeyFor(ORIGINAL_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
                jwt = Jwts.builder()
                        .issuer("GohulSecurityApplication")
                        .claim("USER_ID", authAfter.getName())
                        .claim("USER_AUTHORITIES", authAfter.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.joining(",")))
                        .issuedAt(new Date())
                        .expiration(new Date((new Date()).getTime() + TIMEOUT))
                        .signWith(decodedKey)
                        .compact();
            }
            LoginResponseDto res = new LoginResponseDto(HttpStatus.OK.getReasonPhrase(), "Bearer "+jwt);
            return ResponseEntity.status(HttpStatus.OK).header(MyAppConstant.AUTH_HEADER, jwt).body(res);
        }catch (Exception e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("ErrorReason", e.getMessage()));
        }
    }

    @GetMapping("/public")
    public ResponseEntity<?> publicEndPoint()
    {
        return ResponseEntity.ok("This is a public endpoint!");
    }

    @GetMapping("/user")
    public ResponseEntity<?> userEndPoint()
    {
        return ResponseEntity.ok("Yes this end point is only for person having user role");
    }

    @GetMapping("/admin")
    public ResponseEntity<?> adminEndPoint()
    {
        return ResponseEntity.ok("Yes this end point is only for person having admin role");
    }

    @GetMapping("/authority") // ADMIN_READ
    public ResponseEntity<?> specificAuthorityAccess()
    {
        return ResponseEntity.ok("This endpoint only for the person who having 'ADMIN_READ' authority");
    }

    @GetMapping("/auth2") // ADMIN, ADMIN_WRITE
    public ResponseEntity<?> authorityAccess()
    {
        return ResponseEntity.ok("This end point is only for the people having ADMIN, ADMIN_WRITE role/authority");
    }

    @GetMapping("/session_invalid")
    public ResponseEntity<?> invalidSession()
    {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body("session got invalid");
    }

    @GetMapping("/session_expired")
    public ResponseEntity<?> expiredSession()
    {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body("session got expired");
    }



}
