package com.zen.apigateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
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

import reactor.core.publisher.Mono;

@Component
public class AuthValidationFilter implements GlobalFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthValidationFilter.class);

    private final WebClient.Builder webClientBuilder;
    private final DiscoveryClient discoveryClient;

    @Autowired
    public AuthValidationFilter(WebClient.Builder webClientBuilder, DiscoveryClient discoveryClient) {
        this.webClientBuilder = webClientBuilder;
        this.discoveryClient = discoveryClient;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestId = UUID.randomUUID().toString();
        log.info("🔎 [INIT] Generated X-Request-ID: {}", requestId);

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-Request-ID", requestId)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

        String path = mutatedRequest.getURI().getPath();
        log.info("📥 [REQUEST] Incoming path: {} | Method: {}", path, mutatedRequest.getMethod());

        // Skip auth for public endpoints
        if (path.startsWith("/auth/login") || path.startsWith("/auth/createAccount")) {
            log.info("🔓 [PUBLIC] Skipping auth for public path: {}", path);
            logAuthServiceInstances();
            return chain.filter(mutatedExchange)
                    .doFinally(signal -> log.info("✅ [FORWARD] Request passed to auth-service for path: {}", path));
        }

        // Check auth header
        String authHeader = mutatedRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("🚫 [AUTH] Missing or malformed Authorization header.");
            return respondUnauthorized(mutatedExchange, "Missing or invalid token");
        }

        log.info("🛂 [AUTH] Validating token via auth-service...");

        return webClientBuilder.build()
                .post()
                .uri("lb://auth-service/auth/validate")
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .retrieve()
                .toEntity(String.class)
                .flatMap(responseEntity -> {
                    HttpStatus status = HttpStatus.resolve(responseEntity.getStatusCode().value());
                    if (status == null) status = HttpStatus.INTERNAL_SERVER_ERROR;

                    log.debug("📬 [AUTH-RESPONSE] Status: {} | Body: {}", status, responseEntity.getBody());

                    if (status.is2xxSuccessful()) {
                        try {
                            ObjectMapper mapper = new ObjectMapper();
                            Map<String, Object> body = mapper.readValue(responseEntity.getBody(), Map.class);
                            Map<String, String> data = (Map<String, String>) body.get("data");

                            String email = data.get("email");
                            String tenantId = data.get("tenantId");

                            log.info("✅ [AUTH-SUCCESS] User: {} | Tenant: {}", email, tenantId);

                            ServerHttpRequest enrichedRequest = mutatedRequest.mutate()
                                    .header("X-User-Id", email)
                                    .header("X-Tenant-Id", tenantId)
                                    .build();

                            return chain.filter(mutatedExchange.mutate().request(enrichedRequest).build());

                        } catch (Exception e) {
                            log.error("❌ [PARSING] Failed to parse auth-service response: {}", e.getMessage());
                            return respondUnauthorized(mutatedExchange, "Invalid auth response format");
                        }
                    } else {
                        log.warn("🚫 [AUTH-FAIL] Status: {} | Body: {}", status, responseEntity.getBody());

                        // Forward the response body as-is, preserving CRM service’s error (e.g., 409)
                        mutatedExchange.getResponse().setStatusCode(status);
                        mutatedExchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

                        return mutatedExchange.getResponse().setComplete();
                    }
                })
                .onErrorResume(ex -> {
                    log.error("💥 [EXCEPTION] Auth-service error: {}", ex.getMessage());
                    return respondUnauthorized(mutatedExchange, "Auth service unreachable");
                });
    }

    private void logAuthServiceInstances() {
        List<ServiceInstance> instances = discoveryClient.getInstances("auth-service");
        if (instances.isEmpty()) {
            log.warn("⚠️ [DISCOVERY] No instances found for auth-service.");
        } else {
            log.debug("📡 [DISCOVERY] auth-service instances:");
            for (ServiceInstance instance : instances) {
                log.debug("➡️ Host: {} | Port: {} | URI: {}", instance.getHost(), instance.getPort(), instance.getUri());
            }
        }
    }

    private Mono<Void> respondUnauthorized(ServerWebExchange exchange, String reason) {
        if (exchange.getResponse().isCommitted()) {
            log.warn("⚠️ [RESPONSE] Already committed. Skipping response write.");
            return Mono.empty();
        }

        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorJson = String.format("""
            {
                "timestamp": "%s",
                "status": 401,
                "error": "%s",
                "path": "%s",
                "data": null
            }
            """, java.time.ZonedDateTime.now(), reason, exchange.getRequest().getPath().value());

        DataBuffer buffer = exchange.getResponse().bufferFactory()
                .wrap(errorJson.getBytes(StandardCharsets.UTF_8));

        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
