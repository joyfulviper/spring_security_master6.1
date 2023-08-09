package com.prgrms.devcourse.user;

import com.prgrms.devcourse.jwt.JwtAuthentication;
import com.prgrms.devcourse.jwt.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    public UserController(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/users/login")
    public UserResponse login(@RequestBody loginRequest request) {
        var authToken = new JwtAuthenticationToken(request.principal(), request.credentials());
        var resultToken = authenticationManager.authenticate(authToken);
        var authenticated = (JwtAuthenticationToken) resultToken;
        var principal = (JwtAuthentication) authenticated.getPrincipal();
        var user = (User) authenticated.getDetails();

        return new UserResponse(principal.token, principal.username, user.getGroup().getName());
    }

    @GetMapping("/users/me")
    public UserResponse me(@AuthenticationPrincipal JwtAuthentication authentication) {
        var user = userService.findByLoginId(authentication.username);
        return new UserResponse(authentication.token, authentication.username, user.getGroup().getName());

    }
}