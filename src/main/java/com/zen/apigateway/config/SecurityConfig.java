package com.zen.apigateway.config;

import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

		@Bean
	    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

	        http
	            .csrf(ServerHttpSecurity.CsrfSpec::disable) // Disable CSRF protection
	            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Enable CORS
	            .authorizeExchange(exchanges -> exchanges
	                .anyExchange().permitAll()
	            );

	        return http.build();
	    }

	    @Bean
	    public CorsConfigurationSource corsConfigurationSource() {

	        CorsConfiguration config = new CorsConfiguration();
	        config.setAllowedOrigins(List.of("http://localhost:3000")); // Your frontend origin
	        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
	        config.setAllowedHeaders(List.of("*"));
	        config.setAllowCredentials(true); // Required for cookies or Authorization headers

	        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	        source.registerCorsConfiguration("/**", config);

	        return source;
	    }
    
    @Bean
    @LoadBalanced
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }
}
