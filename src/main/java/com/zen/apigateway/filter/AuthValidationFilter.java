package com.zen.apigateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.databind.ObjectMapper;

import reactor.core.publisher.Mono;

@Component
public class AuthValidationFilter implements GlobalFilter {

	@Autowired
    private final WebClient.Builder webClientBuilder;

    public AuthValidationFilter(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // ⛔ Skip authentication for public endpoints
        if (path.startsWith("/auth/login") || path.startsWith("/auth/createAccount")) {
            return chain.filter(exchange);
        }

        // ✅ JWT validation for other endpoints
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return webClientBuilder.build()
                .post()
                .uri("lb://auth-service/auth/validate")
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .retrieve()
                .toEntity(String.class)
                .flatMap(responseEntity -> {
                    if (responseEntity.getStatusCode().is2xxSuccessful()) {
                        ObjectMapper objectMapper = new ObjectMapper();
                        Map<String, Object> body;
                        try {
                            body = objectMapper.readValue(responseEntity.getBody(), Map.class);
                        } catch (Exception e) {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        }

                        Map<String, String> data = (Map<String, String>) body.get("data");
                        ServerHttpRequest mutated = exchange.getRequest().mutate()
                                .header("X-User-Id", data.get("email"))
                                .header("X-Tenant-Id", data.get("tenantId"))
                                .build();

                        return chain.filter(exchange.mutate().request(mutated).build());
                    } else {
                        exchange.getResponse().setStatusCode(responseEntity.getStatusCode());
                        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                        DataBuffer buffer = exchange.getResponse()
                                .bufferFactory()
                                .wrap(responseEntity.getBody().getBytes(StandardCharsets.UTF_8));
                        return exchange.getResponse().writeWith(Mono.just(buffer));
                    }
                })
                .onErrorResume(ex -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    String errorJson = """
                        {
                            "success": false,
                            "message": "Unauthorized - Token invalid or Auth Service error",
                            "data": null
                        }
                        """;
                    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(errorJson.getBytes(StandardCharsets.UTF_8));
                    return exchange.getResponse().writeWith(Mono.just(buffer));
                });

    }
}
