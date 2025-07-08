package com.zen.apigateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger log = LoggerFactory.getLogger(AuthValidationFilter.class);

    private final WebClient.Builder webClientBuilder;

    @Autowired
    public AuthValidationFilter(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Generate a unique request ID for tracing
        String requestId = UUID.randomUUID().toString();
        log.info("✅ Generated X-Request-ID: {}", requestId);

        // Mutate the original request to include X-Request-ID
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-Request-ID", requestId)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

        String path = mutatedRequest.getURI().getPath();
        log.info("🔀 Incoming request path: {}", path);

        // Skip authentication for public endpoints
        if (path.startsWith("/auth/login") || path.startsWith("/auth/createAccount")) {
            log.info("🔓 Public endpoint accessed, skipping auth: {}", path);
            return chain.filter(mutatedExchange)
                .doFinally(signal -> log.info("➡️ Forwarded to service: auth-service | path: {}", path));
        }

        // Extract Authorization header
        String authHeader = mutatedRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("⛔ Missing or invalid Authorization header");
            mutatedExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return mutatedExchange.getResponse().setComplete();
        }

        log.info("🛡️ Validating JWT token via auth-service");

        return webClientBuilder.build()
                .post()
                .uri("lb://auth-service/auth/validate")
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .retrieve()
                .toEntity(String.class)
                .flatMap(responseEntity -> {
                    if (responseEntity.getStatusCode().is2xxSuccessful()) {
                        try {
                            ObjectMapper objectMapper = new ObjectMapper();
                            Map<String, Object> body = objectMapper.readValue(responseEntity.getBody(), Map.class);
                            Map<String, String> data = (Map<String, String>) body.get("data");

                            String email = data.get("email");
                            String tenantId = data.get("tenantId");

                            log.info("✅ Auth success for user: {} | tenant: {}", email, tenantId);

                            // Mutate request again with user-specific headers
                            ServerHttpRequest enrichedRequest = mutatedRequest.mutate()
                                    .header("X-User-Id", email)
                                    .header("X-Tenant-Id", tenantId)
                                    .build();

                            return chain.filter(mutatedExchange.mutate().request(enrichedRequest).build());

                        } catch (Exception e) {
                            log.error("❌ Failed to parse auth service response: {}", e.getMessage());
                            mutatedExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return mutatedExchange.getResponse().setComplete();
                        }

                    } else {
                        log.warn("❌ Auth service returned non-200: {} - {}",
                                responseEntity.getStatusCode(), responseEntity.getBody());

                        mutatedExchange.getResponse().setStatusCode(responseEntity.getStatusCode());
                        mutatedExchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                        DataBuffer buffer = mutatedExchange.getResponse()
                                .bufferFactory()
                                .wrap(responseEntity.getBody().getBytes(StandardCharsets.UTF_8));
                        return mutatedExchange.getResponse().writeWith(Mono.just(buffer));
                    }
                })
                .onErrorResume(ex -> {
                    log.error("❌ Exception while calling auth-service: {}", ex.getMessage());
                    mutatedExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    mutatedExchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    String errorJson = """
                        {
                            "success": false,
                            "message": "Unauthorized - Token invalid or Auth Service error",
                            "data": null
                        }
                        """;
                    DataBuffer buffer = mutatedExchange.getResponse()
                            .bufferFactory()
                            .wrap(errorJson.getBytes(StandardCharsets.UTF_8));
                    return mutatedExchange.getResponse().writeWith(Mono.just(buffer));
                });
    }
}
