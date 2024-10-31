package com.example.secutraining.controllers;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.secutraining.dto.LoginResponse;
import com.example.secutraining.entities.User;
import com.example.secutraining.repositories.RoleRepository;
import com.example.secutraining.repositories.UserRepository;
import com.example.secutraining.services.TokenService;


@RestController
@RequestMapping("auth")
public class AuthController {

    private final UserRepository userRepository;
    private final AuthenticationManager authManager;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public AuthController(PasswordEncoder passwordEncoderInjected, UserRepository userRepositoryInjected, RoleRepository roleRepositoryInjected, AuthenticationManager authManagerInjected,TokenService tokenServiceInjected) {
        this.authManager = authManagerInjected;
        this.passwordEncoder = passwordEncoderInjected;
        this.userRepository = userRepositoryInjected;
        this.tokenService = tokenServiceInjected;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody User user) {
        Authentication auth = this.authManager.authenticate(new UsernamePasswordAuthenticationToken(
                user.getUsername(), user.getPassword()
        ));
        String token = tokenService.generateToken(auth);
        // récupère l'utilisateur connecté
        User userConnected = (User) auth.getPrincipal();

        return new LoginResponse(token, userConnected);
    }



    @PostMapping("/register")
    public User registerUser(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

}
