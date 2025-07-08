package com.zen.apigateway.config;

import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.reactive.server.ReactiveWebServerFactory;
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
import reactor.netty.http.server.HttpServer;
import javax.net.ssl.KeyManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
	
	/*
	 * @Bean public ReactiveWebServerFactory reactiveWebServerFactory() {
	 * NettyReactiveWebServerFactory factory = new NettyReactiveWebServerFactory();
	 * factory.addServerCustomizers(httpServer -> { try { // Load your keystore
	 * KeyStore keyStore = KeyStore.getInstance("PKCS12"); InputStream
	 * keyStoreStream = getClass().getResourceAsStream("/keystore.p12");
	 * keyStore.load(keyStoreStream, "password".toCharArray());
	 * 
	 * KeyManagerFactory keyManagerFactory =
	 * KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	 * keyManagerFactory.init(keyStore, "password".toCharArray());
	 * 
	 * // Use Netty's SslContextBuilder (not Java SSLContext) SslContext sslContext
	 * = SslContextBuilder .forServer(keyManagerFactory) .protocols("TLSv1.3",
	 * "TLSv1.2", "TLSv1.1") .build();
	 * 
	 * return HttpServer.create().secure(sslContextSpec -> {
	 * sslContextSpec.sslContext(sslContext); }); } catch (Exception e) { throw new
	 * RuntimeException("Failed to configure Netty SSL", e); } });
	 * 
	 * return factory; }
	 */

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
