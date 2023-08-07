package com.prgrms.devcourse.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEventHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @EventListener
    @Async
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        try {
            Thread.sleep(5000L);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        var authentication = event.getAuthentication();

        logger.info("User {} login success", authentication.getPrincipal());
    }

    @EventListener
    public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        var e = event.getException();
        var authentication = event.getAuthentication();

        logger.warn("User {} login failure", authentication.getPrincipal(), e);
    }
}