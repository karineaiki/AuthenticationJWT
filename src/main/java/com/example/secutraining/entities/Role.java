package com.example.secutraining.entities;

import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;

@Entity
public class Role implements GrantedAuthority {
    @Id
    private String name;
    @ManyToMany(mappedBy = "roles")
    private Set<User> users;

    public Role() {
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<User> getUsers() {
        return this.users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    @Override
    public String getAuthority() {
        // n'oublie pas de retourner le nom du rôle ici !
        return this.name;
    }

}
