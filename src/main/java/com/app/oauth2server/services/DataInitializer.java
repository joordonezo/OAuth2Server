package com.app.oauth2server.services;

import com.app.oauth2server.entities.Authorities;
import com.app.oauth2server.entities.Users;
import com.app.oauth2server.repositories.AuthoritiesRepository;
import com.app.oauth2server.repositories.UsersRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UsersRepository usersRepository;
    private final AuthoritiesRepository authoritiesRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        initializeUsers();
        initializeAuthorities();
    }

    private void initializeUsers() {
        // Admin user
        usersRepository.findByUsername("admin")
                .flatMap(existingUser -> {
                    // Si el usuario existe con {noop}, lo eliminamos y recreamos
                    if (existingUser.getPassword().startsWith("{noop}")) {
                        log.info("Eliminando usuario admin con contraseña {noop} para recrear con BCrypt");
                        return usersRepository.delete(existingUser)
                                .then(usersRepository.save(Users.builder()
                                        .username("admin")
                                        .password(passwordEncoder.encode("admin"))
                                        .roles(Set.of("USER", "ADMIN"))
                                        .enabled(true)
                                        .build())
                                        .doOnSuccess(user -> log.info("Usuario admin recreado con BCrypt"))
                                );
                    }
                    return usersRepository.save(existingUser);
                })
                .switchIfEmpty(
                        usersRepository.save(Users.builder()
                                .username("admin")
                                .password(passwordEncoder.encode("admin"))
                                .roles(Set.of("USER", "ADMIN"))
                                .enabled(true)
                                .build())
                                .doOnSuccess(user -> log.info("Usuario admin creado con BCrypt"))
                )
                .subscribe();

        // Jorge user
        usersRepository.findByUsername("jorge")
                .flatMap(existingUser -> {
                    // Si el usuario existe con {noop}, lo eliminamos y recreamos
                    if (existingUser.getPassword().startsWith("{noop}")) {
                        log.info("Eliminando usuario jorge con contraseña {noop} para recrear con BCrypt");
                        return usersRepository.delete(existingUser)
                                .then(usersRepository.save(Users.builder()
                                        .username("jorge")
                                        .password(passwordEncoder.encode("password"))
                                        .roles(Set.of("USER"))
                                        .enabled(true)
                                        .build())
                                        .doOnSuccess(user -> log.info("Usuario jorge recreado con BCrypt"))
                                );
                    }
                    return usersRepository.save(existingUser);
                })
                .switchIfEmpty(
                        usersRepository.save(Users.builder()
                                .username("jorge")
                                .password(passwordEncoder.encode("password"))
                                .roles(Set.of("USER"))
                                .enabled(true)
                                .build())
                                .doOnSuccess(user -> log.info("Usuario jorge creado con BCrypt"))
                )
                .subscribe();
    }

    private void initializeAuthorities() {
        authoritiesRepository.findByClientId("client-app")
                .flatMap(existingAuthority -> {
                    // Si la authority existe con {noop}, la eliminamos y recreamos
                    if (existingAuthority.getClientSecret().startsWith("{noop}")) {
                        log.info("Eliminando authority client-app con client secret {noop} para recrear con BCrypt");
                        return authoritiesRepository.delete(existingAuthority)
                                .then(authoritiesRepository.save(Authorities.builder()
                                        .id(UUID.randomUUID().toString())
                                        .clientId("client-app")
                                        .clientSecret(passwordEncoder.encode("password"))
                                        .clientAuthenticationMethods(Set.of("client_secret_basic"))
                                        .authorizationGrantTypes(Set.of("authorization_code", "refresh_token"))
                                        .redirectUris(Set.of(
                                                "http://127.0.0.1:9000/login/oauth2/code/client-app",
                                                "http://127.0.0.1:9000/authorized"
                                        ))
                                        .postLogoutRedirectUris(Set.of("http://127.0.0.1:9000/logout"))
                                        .scopes(Set.of("openid", "profile", "read", "write"))
                                        .requireAuthorizationConsent(false)
                                        .build())
                                        .doOnSuccess(auth -> log.info("Authority client-app recreada con BCrypt"))
                                );
                    }
                    return authoritiesRepository.save(existingAuthority);
                })
                .switchIfEmpty(
                        authoritiesRepository.save(Authorities.builder()
                                .id(UUID.randomUUID().toString())
                                .clientId("client-app")
                                .clientSecret(passwordEncoder.encode("password"))
                                .clientAuthenticationMethods(Set.of("client_secret_basic"))
                                .authorizationGrantTypes(Set.of("authorization_code", "refresh_token"))
                                .redirectUris(Set.of(
                                        "http://127.0.0.1:9000/login/oauth2/code/client-app",
                                        "http://127.0.0.1:9000/authorized"
                                ))
                                .postLogoutRedirectUris(Set.of("http://127.0.0.1:9000/logout"))
                                .scopes(Set.of("openid", "profile", "read", "write"))
                                .requireAuthorizationConsent(false)
                                .build())
                                .doOnSuccess(auth -> log.info("Authority client-app creada con BCrypt"))
                )
                .subscribe();
    }
}
