package com.prgrms.devcourse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class SsmcApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsmcApplication.class, args);
    }
}