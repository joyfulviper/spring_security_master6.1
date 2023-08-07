package com.prgrms.devcourse.user;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "groups")
public class Group {

    @Id
    @Column(name = "id")
    private Long id;

    @Column(name = "name")
    private String name;

    @OneToMany(mappedBy = "group")
    private List<GroupPermission> permissions = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public List<SimpleGrantedAuthority> getAuthorities() {
        return permissions.stream()
                .map(gp -> new SimpleGrantedAuthority(gp.getPermission().getName()))
                .toList();
    }

    @Override
    public String toString() {
        return "Group{" +
                "id=" + id +
                ", name='" + name + '\'' +
                "authorities" + getAuthorities() +
                '}';
    }
}