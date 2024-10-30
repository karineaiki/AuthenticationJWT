package com.example.secutraining;

import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.secutraining.entities.DemoEntity;
import com.example.secutraining.entities.Role;
import com.example.secutraining.entities.User;
import com.example.secutraining.repositories.DemoRepository;
import com.example.secutraining.repositories.RoleRepository;
import com.example.secutraining.repositories.UserRepository;

@SpringBootApplication
public class SecutrainingApplication {

	public static void main(String[] args) {
		System.setProperty("spring.profiles.active", "dev");
		SpringApplication.run(SecutrainingApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner(DemoRepository demoRepository, UserRepository userRepository,
			RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
		return args -> {
			demoRepository.save(new DemoEntity("Tacos"));

			// manually creates roles and users on startup
			Role roleUser = new Role();
			roleUser.setName("ROLE_USER");
			roleUser = roleRepository.save(roleUser);
			Role roleAdmin = new Role();
			roleAdmin.setName("ROLE_ADMIN");
			roleAdmin = roleRepository.save(roleAdmin);

			User admin = new User();
			admin.setUsername("admin@example.com");
			admin.setPassword(passwordEncoder.encode("securepassword"));
			admin.setRoles(Set.of(roleAdmin));
			userRepository.save(admin);

			User user = new User();
			user.setUsername("bastien@example.com");
			user.setPassword(passwordEncoder.encode("tacostacos"));
			user.setRoles(Set.of(roleUser));
			userRepository.save(user);
		};
	}

}
