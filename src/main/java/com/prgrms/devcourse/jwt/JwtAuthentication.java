package com.prgrms.devcourse.jwt;

import static com.google.common.base.Preconditions.checkArgument;
import static io.micrometer.common.util.StringUtils.isNotEmpty;

public class JwtAuthentication {

    public final String token;

    public final String username;


    public JwtAuthentication(String token, String username) {
        checkArgument(isNotEmpty(token), "token must be provided");
        checkArgument(isNotEmpty(username), "username must be provided");

        this.token = token;
        this.username = username;
    }
}