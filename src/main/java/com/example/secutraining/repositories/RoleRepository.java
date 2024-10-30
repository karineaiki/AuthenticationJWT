package com.example.secutraining.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.secutraining.entities.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {

}
