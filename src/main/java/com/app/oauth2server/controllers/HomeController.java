package com.app.oauth2server.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Authentication authentication) {
        // Si el usuario tiene rol ADMIN, redirigir a usuarios
        if (authentication != null &&
            authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
            return "redirect:/users";
        }
        // Si no es admin, redirigir a una página de bienvenida o error
        return "redirect:/login";
    }
}
