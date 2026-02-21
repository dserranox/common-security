package ar.com.dserrano.common.security;

import ar.com.dserrano.common.security.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class JwtAutoConfiguration {

    @Bean
    public JwtTokenProvider jwtTokenProvider(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.exp-minutes:120}") long expirationMinutes) {
        return new JwtTokenProvider(secret, expirationMinutes);
    }
}
