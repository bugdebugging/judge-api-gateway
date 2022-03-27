package com.anny.demo2.config;

import com.auth0.jwt.exceptions.JWTVerificationException;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Component
@RequiredArgsConstructor
public class JwtValidateFilter extends AbstractGatewayFilterFactory {
    private final JwtUtils jwtUtils;
    private final static String AUTHORIZATION_PREFIX = "Bearer ";

    @Override
    public GatewayFilter apply(Object config) {
        return ((exchange, chain) -> {
            String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (isNotEmpty(token) && token.contains(AUTHORIZATION_PREFIX)) {
                try {
                    exchange.getRequest().mutate()
                            .header("X-USERNAME", getToken(token))
                            .build();
                } catch (JWTVerificationException e) {
                }
            }
            return chain.filter(exchange);
        });
    }

    private String getToken(String token) {
        return jwtUtils.validate(token.substring(AUTHORIZATION_PREFIX.length()));
    }
}
