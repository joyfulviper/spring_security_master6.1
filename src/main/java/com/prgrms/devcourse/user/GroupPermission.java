package com.prgrms.devcourse.user;

import jakarta.persistence.*;

@Entity
@Table(name = "group_permission")
public class GroupPermission {

    @Id
    @Column(name = "id")
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "group_id")
    private Group group;

    @ManyToOne(optional = false)
    @JoinColumn(name = "permission_id")
    private Permission permission;

    public void setGroup(Group group) {
        this.group = group;
    }

    public void setPermission(Permission permission) {
        this.permission = permission;
    }

    public Permission getPermission() {
        return permission;
    }

    public Group getGroup() {
        return group;
    }
}