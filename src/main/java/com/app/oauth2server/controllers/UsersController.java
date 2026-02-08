package com.app.oauth2server.controllers;

import com.app.oauth2server.entities.Users;
import com.app.oauth2server.repositories.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;

import java.util.HashSet;

@Controller
@RequestMapping("/users")
@RequiredArgsConstructor
public class UsersController {

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    @GetMapping
    public String listUsers(Model model) {
        Flux<Users> users = usersRepository.findAll();
        model.addAttribute("users", users.collectList().block());
        return "users/list";
    }

    @GetMapping("/new")
    public String newUser(Model model) {
        model.addAttribute("user", new Users());
        model.addAttribute("isNew", true);
        return "users/form";
    }

    @GetMapping("/edit/{id}")
    public String editUser(@PathVariable String id, Model model) {
        Users user = usersRepository.findById(id).block();
        model.addAttribute("user", user);
        model.addAttribute("isNew", false);
        return "users/form";
    }

    @PostMapping("/save")
    public String saveUser(
            @RequestParam(required = false) String id,
            @RequestParam String username,
            @RequestParam(required = false) String password,
            @RequestParam(required = false) String[] roles,
            @RequestParam(defaultValue = "false") boolean enabled) {

        Users user;

        if (id != null && !id.isEmpty()) {
            // Editando usuario existente
            user = usersRepository.findById(id).block();
            if (user != null) {
                user.setUsername(username);
                // Solo actualizar contraseña si se proporciona una nueva
                if (password != null && !password.trim().isEmpty()) {
                    user.setPassword(passwordEncoder.encode(password));
                }
                user.setRoles(convertArrayToSet(roles));
                user.setEnabled(enabled);
            }
        } else {
            // Nuevo usuario
            user = Users.builder()
                    .username(username)
                    .password(passwordEncoder.encode(password))
                    .roles(convertArrayToSet(roles))
                    .enabled(enabled)
                    .build();
        }

        if (user != null) {
            usersRepository.save(user).block();
        }

        return "redirect:/users";
    }

    @GetMapping("/delete/{id}")
    public String deleteUser(@PathVariable String id) {
        usersRepository.deleteById(id).block();
        return "redirect:/users";
    }

    private HashSet<String> convertArrayToSet(String[] array) {
        HashSet<String> set = new HashSet<>();
        if (array != null) {
            for (String item : array) {
                if (item != null && !item.trim().isEmpty()) {
                    set.add(item.trim());
                }
            }
        }
        return set;
    }
}
