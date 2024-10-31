package com.example.secutraining.controllers;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.secutraining.entities.DemoEntity;
import com.example.secutraining.repositories.DemoRepository;

@RestController
@RequestMapping("api/demo")
public class DemoController {

    private final DemoRepository demoRepository;

    public DemoController(DemoRepository demoRepository) {
        this.demoRepository = demoRepository;
    }

    @GetMapping("/user")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_USER')")
    public String userAccess() {
        return "User access";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    public String adminAccess() {
        return "Admin access";
    }

}
