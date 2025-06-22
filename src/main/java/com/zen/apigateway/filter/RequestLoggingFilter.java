package com.zen.apigateway.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Extract or generate the request ID
        String requestId = Optional.ofNullable(request.getHeader("X-Request-ID"))
                                   .orElse(UUID.randomUUID().toString());

        String sessionId = request.getSession(false) != null
                ? request.getSession().getId()
                : "no-session";

        MDC.put("requestId", requestId);
        MDC.put("sessionId", sessionId);

        try {
            log.info("➡ Incoming Request: {} {} | SessionID: {} | RequestID: {}",
                    request.getMethod(), request.getRequestURI(), sessionId, requestId);

            response.setHeader("X-Request-ID", requestId); // include in response

            filterChain.doFilter(request, response);

            log.info("⬅ Response: {} {} | Status: {} | RequestID: {}",
                    request.getMethod(), request.getRequestURI(), response.getStatus(), requestId);

        } finally {
            MDC.clear(); // clean up
        }
    }
}
