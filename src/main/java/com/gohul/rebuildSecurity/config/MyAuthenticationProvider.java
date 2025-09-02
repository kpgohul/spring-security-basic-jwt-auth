package com.gohul.rebuildSecurity.config;

import com.gohul.rebuildSecurity.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class MyAuthenticationProvider implements AuthenticationProvider {

    private final MyUserDetailsService userDetailsService;
    private final PasswordEncoder encoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String value = authentication.getName();
        String rawPas = authentication.getCredentials().toString();
        UserDetails user = userDetailsService.loadUserByUsername(value);
        if(encoder.matches(rawPas, user.getPassword()))
            return new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities());
        throw  new BadCredentialsException("Password is not match for the given user details:: "+ value);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
