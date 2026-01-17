package com.confiance.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Security configuration for API Gateway.
 * Disables CSRF protection since this is a stateless REST API using JWT tokens.
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)  // Disable CSRF for stateless API
                .authorizeExchange(exchange -> exchange
                        .anyExchange().permitAll()  // Allow all requests to pass through
                );

        return http.build();
    }
}