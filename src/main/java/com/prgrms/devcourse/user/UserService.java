package com.prgrms.devcourse.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByLoginId(username)
                .map(user -> User.builder()
                        .username(user.getLoginId())
                        .password(user.getPassword())
                        .authorities(user.getGroup().getAuthorities())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found user for login id: " + username));
    }
}