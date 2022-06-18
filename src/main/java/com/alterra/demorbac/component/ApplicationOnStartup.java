package com.alterra.demorbac.component;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.alterra.demorbac.model.User;
import com.alterra.demorbac.model.UserRole;
import com.alterra.demorbac.repository.UserRepository;
import com.alterra.demorbac.repository.UserRoleRepository;

/**
 * This class is used to create dummy data on application startup.
 */
@Component
public class ApplicationOnStartup implements ApplicationListener<ApplicationReadyEvent> {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        User admin = User.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("admin"))
                        .businessTitle("Administrator")
                        .fullName("Maverick J. Robert")
                        .build();
        User user = User.builder()
                        .username("user")
                        .password(passwordEncoder.encode("user"))
                        .businessTitle("Only User")
                        .fullName("User Dummy")
                        .build();
        List<User> users = new ArrayList<>();
        users.add(admin);
        users.add(user);

        userRepository.saveAll(users);

        UserRole adminRoleAdmin = UserRole.builder()
                                .user(admin)
                                .role("ROLE_ADMIN")
                                .build();
        UserRole adminRoleUser = UserRole.builder()
                                .user(admin)
                                .role("ROLE_USER")
                                .build();
        UserRole userRoleUser = UserRole.builder()
                                .user(user)
                                .role("ROLE_USER")
                                .build();
        List<UserRole> userRoles = new ArrayList<>();
        userRoles.add(adminRoleAdmin);
        userRoles.add(adminRoleUser);
        userRoles.add(userRoleUser);

        userRoleRepository.saveAll(userRoles);
    }
    
}
