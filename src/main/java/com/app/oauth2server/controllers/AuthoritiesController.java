package com.app.oauth2server.controllers;

import com.app.oauth2server.entities.Authorities;
import com.app.oauth2server.repositories.AuthoritiesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;

import java.util.HashSet;
import java.util.UUID;

@Controller
@RequestMapping("/authorities")
@RequiredArgsConstructor
public class AuthoritiesController {

    private final AuthoritiesRepository authoritiesRepository;

    @GetMapping
    public String listAuthorities(Model model) {
        Flux<Authorities> authorities = authoritiesRepository.findAll();
        model.addAttribute("authorities", authorities.collectList().block());
        return "authorities/list";
    }

    @GetMapping("/new")
    public String newAuthority(Model model) {
        model.addAttribute("authority", new Authorities());
        return "authorities/form";
    }

    @GetMapping("/edit/{id}")
    public String editAuthority(@PathVariable String id, Model model) {
        Authorities authority = authoritiesRepository.findById(id).block();
        model.addAttribute("authority", authority);
        return "authorities/form";
    }

    @PostMapping("/save")
    public String saveAuthority(
            @RequestParam(required = false) String id,
            @RequestParam String clientId,
            @RequestParam String clientSecret,
            @RequestParam(required = false) String[] clientAuthenticationMethods,
            @RequestParam(required = false) String[] authorizationGrantTypes,
            @RequestParam(required = false) String[] redirectUris,
            @RequestParam(required = false) String[] postLogoutRedirectUris,
            @RequestParam(required = false) String[] scopes,
            @RequestParam(defaultValue = "false") boolean requireAuthorizationConsent) {

        Authorities authority = Authorities.builder()
                .id(id != null && !id.isEmpty() ? id : UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethods(convertArrayToSet(clientAuthenticationMethods))
                .authorizationGrantTypes(convertArrayToSet(authorizationGrantTypes))
                .redirectUris(convertArrayToSet(redirectUris))
                .postLogoutRedirectUris(convertArrayToSet(postLogoutRedirectUris))
                .scopes(convertArrayToSet(scopes))
                .requireAuthorizationConsent(requireAuthorizationConsent)
                .build();

        authoritiesRepository.save(authority).block();
        return "redirect:/authorities";
    }

    @GetMapping("/delete/{id}")
    public String deleteAuthority(@PathVariable String id) {
        authoritiesRepository.deleteById(id).block();
        return "redirect:/authorities";
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
