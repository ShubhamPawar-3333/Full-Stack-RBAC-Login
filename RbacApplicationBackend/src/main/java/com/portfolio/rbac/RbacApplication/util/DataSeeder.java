package com.portfolio.rbac.RbacApplication.util;

import com.portfolio.rbac.RbacApplication.model.Role;
import com.portfolio.rbac.RbacApplication.model.User;
import com.portfolio.rbac.RbacApplication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataSeeder.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    public void run(String... args) throws Exception {
        if (!userRepository.existsByUsername("admin")) {
            userRepository.save(User.builder()
                            .username("admin")
                            .password(passwordEncoder.encode("admin123"))
                            .role(Role.ADMIN)
                            .enabled(true)
                    .build());
            logger.info("Seeded admin user");
        }
        if (!userRepository.existsByUsername("user")) {
            userRepository.save(User.builder()
                            .username("user")
                            .password(passwordEncoder.encode("user123"))
                            .role(Role.USER)
                            .enabled(true)
                    .build());
            logger.info("Seeded user");
        }
    }
}
