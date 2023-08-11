package com.prgrms.devcourse.user;

import jakarta.persistence.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static io.micrometer.common.util.StringUtils.isNotEmpty;

@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "provider")
    private String provider;

    @Column(name = "provider_id")
    private String providerId;

    @Column(name = "profile_image")
    private String profileImage;

    @ManyToOne(optional = false)
    @JoinColumn(name = "group_id")
    private Group group;

    protected User() {/*no-op*/}

    public User(String username, String provider, String providerId, String profileImage, Group group) {
        checkArgument(isNotEmpty(username), "username must be provided.");
        checkArgument(isNotEmpty(provider), "provider must be provided.");
        checkArgument(isNotEmpty(providerId), "providerId must be provided.");
        checkArgument(group != null, "group must be provided.");

        this.username = username;
        this.provider = provider;
        this.providerId = providerId;
        this.profileImage = profileImage;
        this.group = group;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getProvider() {
        return provider;
    }

    public String getProviderId() {
        return providerId;
    }

    public Optional<String> getProfileImage() {
        return Optional.ofNullable(profileImage);
    }

    public Group getGroup() {
        return group;
    }

}