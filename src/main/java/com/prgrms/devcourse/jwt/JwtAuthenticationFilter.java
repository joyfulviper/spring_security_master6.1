package com.prgrms.devcourse.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static io.micrometer.common.util.StringUtils.isNotEmpty;

public class JwtAuthenticationFilter extends GenericFilterBean {

    private final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private final String headerKey;

    private final Jwt jwt;

    public JwtAuthenticationFilter(String headerKey, Jwt jwt) {
        this.headerKey = headerKey;
        this.jwt = jwt;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        /**
         * HTTP 헤더에 JWT 토큰이 있는지 확인
         * JWT 토큰이 있다면, 주어진 토큰을 디코딩하고
         * username, roles 데이터를 추출하고, UsernamePasswordAuthenticationToken 객체를 생성
         * 그리고 이렇게 만들어진 UsernamePasswordAuthenticationToken 객체를 SecurityContextHolder에 저장
         */

        var request = (HttpServletRequest) servletRequest;
        var response = (HttpServletResponse) servletResponse;

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                var token = getToken(request);
                Optional.ofNullable(token)
                        .map(this::verify)
                        .filter(claims -> isNotEmpty(claims.username) && !getAuthorities(claims).isEmpty())
                        .ifPresent(claims -> {
                            logger.debug("Jwt parsed: {}", claims);
                            var username = claims.username;
                            var authorities = getAuthorities(claims);
                            var authentication = new JwtAuthenticationToken(new JwtAuthentication(token, username),
                                    null,
                                    authorities
                            );
                            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        });
            } catch (Exception e) {
                logger.error("Failed to verify token", e);
                return;
            }
        } else {
            logger.debug("SecurityContextHolder not populated with security token, as it already contained: '{}'",
                    SecurityContextHolder.getContext().getAuthentication());
        }

        filterChain.doFilter(request, response);
    }

    private String getToken(HttpServletRequest request) {
        /**
         * HTTP 헤더에서 JWT 토큰을 추출
         */
        String token = request.getHeader(headerKey);
        if (isNotEmpty(token)) {
            logger.debug("Found token in header: {}", token);
            try {
                return URLDecoder.decode(token, "UTF-8");
            } catch (Exception e) {
                logger.error("Failed to decode token: {}", token, e);
            }
        }

        return null;
    }

    private Jwt.Claims verify(String token) {
        return jwt.verify(token);
    }

    private List<? extends GrantedAuthority> getAuthorities(Jwt.Claims claims) {
        return Optional.ofNullable(claims.roles)
                .filter(roles -> roles.length > 0)
                .map(roles -> Arrays.stream(roles).map(SimpleGrantedAuthority::new).toList())
                .orElse(Collections.emptyList());
    }
}