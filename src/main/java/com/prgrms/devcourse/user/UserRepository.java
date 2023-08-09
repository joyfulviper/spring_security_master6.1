package com.prgrms.devcourse.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u JOIN FETCH u.group g JOIN FETCH g.permissions gp JOIN FETCH gp.permission WHERE u.loginId = :loginId")
    Optional<User> findByLoginIdWithAuthorities(@Param("loginId") String loginId);
}