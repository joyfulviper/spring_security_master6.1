package com.prgrms.devcourse.user;

import com.prgrms.devcourse.jwt.JwtAuthentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(path = "/user/me")
    public UserResponse me(@AuthenticationPrincipal JwtAuthentication authentication) {
        return userService.findByUsername(authentication.username)
                .map(user ->
                        new UserResponse(authentication.token, authentication.username, user.getGroup().getName())
                )
                .orElseThrow(() -> new IllegalArgumentException("Could not found user for " + authentication.username));
    }

}