package com.prgrms.devcourse.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User login(String username, String credentials) {
        var user = userRepository.findByLoginIdWithAuthorities(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found user for login id: " + username));
        user.checkPassword(passwordEncoder, credentials);

        return user;
    }

    public User findByLoginId(String loginId) {
        return userRepository.findByLoginIdWithAuthorities(loginId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found user for login id: " + loginId));
    }



    /*@Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByLoginId(username)
                .map(user -> User.builder()
                        .username(user.getLoginId())
                        .password(user.getPassword())
                        .authorities(user.getGroup().getAuthorities())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found user for login id: " + username));
    }*/
}