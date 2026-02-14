package com.app.oauth2server.services;

import com.app.oauth2server.entities.Authorities;
import com.app.oauth2server.repositories.AuthoritiesRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

@RequiredArgsConstructor
@Slf4j
public class MongoRegisteredClientRepository implements RegisteredClientRepository {

    private final AuthoritiesRepository authoritiesRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        var authority = mapToAuthority(registeredClient);
        authoritiesRepository.save(authority).block();
    }

    @Override
    public RegisteredClient findById(String id) {
        return authoritiesRepository.findById(id)
                .map(this::mapToRegisteredClient)
                .block();
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        try {
            var authority = authoritiesRepository.findByClientId(clientId).block();
            if (authority == null) {
                log.warn("Client not found in MongoDB: {}", clientId);
                return null;
            }
            return mapToRegisteredClient(authority);
        } catch (Exception e) {
            log.error("Error looking up or mapping client {}: {}", clientId, e.getMessage(), e);
            return null;
        }
    }

    private RegisteredClient mapToRegisteredClient(Authorities authority) {
        var builder = RegisteredClient.withId(authority.getId())
                .clientId(authority.getClientId())
                .clientSecret(authority.getClientSecret());

        authority.getClientAuthenticationMethods().forEach(method ->
                builder.clientAuthenticationMethod(new ClientAuthenticationMethod(method)));

        authority.getAuthorizationGrantTypes().forEach(grantType ->
                builder.authorizationGrantType(new AuthorizationGrantType(grantType)));

        authority.getRedirectUris().forEach(builder::redirectUri);
        authority.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
        authority.getScopes().forEach(builder::scope);

        builder.clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(authority.isRequireAuthorizationConsent())
                .build());

        return builder.build();
    }

    private Authorities mapToAuthority(RegisteredClient client) {
        return Authorities.builder()
                .id(client.getId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientAuthenticationMethods(client.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::getValue)
                        .collect(java.util.stream.Collectors.toSet()))
                .authorizationGrantTypes(client.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .collect(java.util.stream.Collectors.toSet()))
                .redirectUris(client.getRedirectUris())
                .postLogoutRedirectUris(client.getPostLogoutRedirectUris())
                .scopes(client.getScopes())
                .requireAuthorizationConsent(client.getClientSettings().isRequireAuthorizationConsent())
                .build();
    }
}
