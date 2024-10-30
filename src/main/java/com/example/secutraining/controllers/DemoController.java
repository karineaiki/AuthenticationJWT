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

    @GetMapping("")
    @PreAuthorize("hasAnyAuthority('SCOPE_ROLE_USER', 'SCOPE_ROLE_ADMIN')") // Accessible par ROLE_USER et ROLE_ADMIN
    public List<DemoEntity> getAll() {
        return this.demoRepository.findAll();
    }

    @PostMapping("")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')") // Accessible par ROLE_ADMIN uniquement
    public DemoEntity createDemo(@RequestBody DemoEntity entity) {
        return this.demoRepository.save(entity);
    }

}
