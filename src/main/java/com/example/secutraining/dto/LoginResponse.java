package com.example.secutraining.dto;

import com.example.secutraining.entities.User;

public record LoginResponse(String token, User user) {
}
