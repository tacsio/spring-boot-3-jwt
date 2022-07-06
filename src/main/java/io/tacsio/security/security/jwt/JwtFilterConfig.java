package io.tacsio.security.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import javax.crypto.SecretKey;

public class JwtFilterConfig extends AbstractHttpConfigurer<JwtFilterConfig, HttpSecurity> {

    private ObjectMapper mapper;
    private JwtConfig jwtConfig;
    private SecretKey secretKey;

    public JwtFilterConfig(ObjectMapper mapper, JwtConfig jwtConfig, SecretKey secretKey) {
        this.mapper = mapper;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

        http
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(mapper, authenticationManager, jwtConfig, secretKey))
                .addFilterBefore(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
        ;
    }

    public static JwtFilterConfig jwtFilters(ObjectMapper mapper, JwtConfig jwtConfig, SecretKey secretKey) {
        return new JwtFilterConfig(mapper, jwtConfig, secretKey);
    }
}
