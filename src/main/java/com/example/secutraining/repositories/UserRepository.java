package com.example.secutraining.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.secutraining.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, String>{

    public Optional<User> findByUsername(String username);
}
