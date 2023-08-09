package com.prgrms.devcourse;

import com.prgrms.devcourse.config.JwtConfigure;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class UserRestControllerTest {

    @Autowired
    private JwtConfigure jwtConfigure;

    @Autowired
    private TestRestTemplate testRestTemplate;

    @Test
    @DisplayName("JWT 토큰 생성 테스트")
    void jwt_토큰_생성_테스트() {
        Assertions.assertThat(tokenToName(getToken("user"))).isEqualTo("user");
        Assertions.assertThat(tokenToName(getToken("admin"))).isEqualTo("admin");
    }

    private String getToken(String username) {
        return testRestTemplate.exchange(
                "/api/users/" + username + "/token",
                HttpMethod.GET,
                null,
                String.class
        ).getBody();
    }

    private String tokenToName(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(jwtConfigure.getHeader(), token);
        return testRestTemplate.exchange(
                "/api/users/me",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        ).getBody();
    }
    


}