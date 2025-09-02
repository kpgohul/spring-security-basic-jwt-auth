package com.gohul.rebuildSecurity.config;

import com.gohul.rebuildSecurity.filter.JwtGeneratorFilter;
import com.gohul.rebuildSecurity.filter.JwtValidatorFilter;
import com.gohul.rebuildSecurity.handler.AuthenticationHandler;
import com.gohul.rebuildSecurity.handler.AuthorizationHandler;
import org.apache.catalina.security.SecurityConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@ComponentScan(basePackages = "com.gohul.rebuildSecurity")
public class ProjectSecurityConfig {

    @Bean
    public SecurityFilterChain customSecurityConfig(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests( req ->
                {
                    req.requestMatchers("/app/sign-up","/app/sign-in", "/app/public", "/app/session_invalid", "/app/session_expired", "/error").permitAll();
                    req.requestMatchers("/app/admin").hasRole("ADMIN");
                    req.requestMatchers("/app/user").hasRole("USER");
                    req.requestMatchers("/app/authority").hasAuthority("ADMIN_READ");
                    req.requestMatchers("/app/auth2").hasAnyAuthority("ROLE_ADMIN", "ADMIN_WRITE");
                });
        http.sessionManagement( smc ->
            {
//                smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                smc.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
                smc.invalidSessionUrl("/app/session_invalid")
                        .maximumSessions(2)
                        .expiredUrl("/app/session_expired");
            }
        );
        http.addFilterBefore(new JwtValidatorFilter(), BasicAuthenticationFilter.class)
            .addFilterAfter(new JwtGeneratorFilter(), BasicAuthenticationFilter.class);
        http.csrf(AbstractHttpConfigurer::disable);
        http.securityContext(scc -> scc.requireExplicitSave(true));
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        http.exceptionHandling(ehc ->
            {
                ehc.authenticationEntryPoint(new AuthenticationHandler());
                ehc.accessDeniedHandler(new AuthorizationHandler());

            });
        return http.build();

    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(MyUserDetailsService userDetailsService, PasswordEncoder encoder)
    {
        MyAuthenticationProvider authProvider = new MyAuthenticationProvider(userDetailsService, encoder);
        ProviderManager manager = new ProviderManager(authProvider);
        manager.setEraseCredentialsAfterAuthentication(true);
        return manager;
    }

}
