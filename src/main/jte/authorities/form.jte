@import com.app.oauth2server.entities.Authorities
@param Authorities authority

@template.layout(
    title = authority.getId() == null ? "Nueva Authority" : "Editar Authority",
    content = @`
        <div class="card">
            <h2>${authority.getId() == null ? "Nueva Authority" : "Editar Authority"}</h2>

            <form action="/authorities/save" method="post">
                @if(authority.getId() != null)
                    <input type="hidden" name="id" value="${authority.getId()}">
                @endif

                <div class="form-group">
                    <label for="clientId">Client ID *</label>
                    <input type="text" id="clientId" name="clientId"
                           value="${authority.getClientId() != null ? authority.getClientId() : ""}"
                           required>
                </div>

                <div class="form-group">
                    <label for="clientSecret">Client Secret *</label>
                    <input type="text" id="clientSecret" name="clientSecret"
                           value="${authority.getClientSecret() != null ? authority.getClientSecret() : ""}"
                           required>
                    <small style="color: #666;">Prefijo {noop} para sin encriptación, o {bcrypt} para bcrypt</small>
                </div>

                <div class="form-group">
                    <label>Client Authentication Methods *</label>
                    <div>
                        <label>
                            <input type="checkbox" name="clientAuthenticationMethods" value="client_secret_basic"
                                   ${authority.getClientAuthenticationMethods() != null && authority.getClientAuthenticationMethods().contains("client_secret_basic") ? "checked" : ""}>
                            client_secret_basic
                        </label>
                    </div>
                    <div>
                        <label>
                            <input type="checkbox" name="clientAuthenticationMethods" value="client_secret_post"
                                   ${authority.getClientAuthenticationMethods() != null && authority.getClientAuthenticationMethods().contains("client_secret_post") ? "checked" : ""}>
                            client_secret_post
                        </label>
                    </div>
                </div>

                <div class="form-group">
                    <label>Authorization Grant Types *</label>
                    <div>
                        <label>
                            <input type="checkbox" name="authorizationGrantTypes" value="authorization_code"
                                   ${authority.getAuthorizationGrantTypes() != null && authority.getAuthorizationGrantTypes().contains("authorization_code") ? "checked" : ""}>
                            authorization_code
                        </label>
                    </div>
                    <div>
                        <label>
                            <input type="checkbox" name="authorizationGrantTypes" value="refresh_token"
                                   ${authority.getAuthorizationGrantTypes() != null && authority.getAuthorizationGrantTypes().contains("refresh_token") ? "checked" : ""}>
                            refresh_token
                        </label>
                    </div>
                    <div>
                        <label>
                            <input type="checkbox" name="authorizationGrantTypes" value="client_credentials"
                                   ${authority.getAuthorizationGrantTypes() != null && authority.getAuthorizationGrantTypes().contains("client_credentials") ? "checked" : ""}>
                            client_credentials
                        </label>
                    </div>
                </div>

                <div class="form-group">
                    <label for="redirectUris">Redirect URIs (uno por línea) *</label>
                    <textarea id="redirectUris" name="redirectUris" rows="3">${authority.getRedirectUris() != null ? String.join("\n", authority.getRedirectUris()) : ""}</textarea>
                </div>

                <div class="form-group">
                    <label for="postLogoutRedirectUris">Post Logout Redirect URIs (uno por línea)</label>
                    <textarea id="postLogoutRedirectUris" name="postLogoutRedirectUris" rows="2">${authority.getPostLogoutRedirectUris() != null ? String.join("\n", authority.getPostLogoutRedirectUris()) : ""}</textarea>
                </div>

                <div class="form-group">
                    <label>Scopes *</label>
                    <div>
                        <label>
                            <input type="checkbox" name="scopes" value="openid"
                                   ${authority.getScopes() != null && authority.getScopes().contains("openid") ? "checked" : ""}>
                            openid
                        </label>
                    </div>
                    <div>
                        <label>
                            <input type="checkbox" name="scopes" value="profile"
                                   ${authority.getScopes() != null && authority.getScopes().contains("profile") ? "checked" : ""}>
                            profile
                        </label>
                    </div>
                    <div>
                        <label>
                            <input type="checkbox" name="scopes" value="read"
                                   ${authority.getScopes() != null && authority.getScopes().contains("read") ? "checked" : ""}>
                            read
                        </label>
                    </div>
                    <div>
                        <label>
                            <input type="checkbox" name="scopes" value="write"
                                   ${authority.getScopes() != null && authority.getScopes().contains("write") ? "checked" : ""}>
                            write
                        </label>
                    </div>
                </div>

                <div class="form-group">
                    <label>
                        <input type="checkbox" name="requireAuthorizationConsent" value="true"
                               ${authority.isRequireAuthorizationConsent() ? "checked" : ""}>
                        Require Authorization Consent
                    </label>
                </div>

                <div class="actions">
                    <button type="submit" class="btn">Guardar</button>
                    <a href="/authorities" class="btn btn-secondary">Cancelar</a>
                </div>
            </form>
        </div>

        <script>
            // Convertir textarea a array en el submit
            document.querySelector('form').addEventListener('submit', function(e) {
                const redirectUris = document.getElementById('redirectUris').value.split('\n').filter(uri => uri.trim());
                const postLogoutUris = document.getElementById('postLogoutRedirectUris').value.split('\n').filter(uri => uri.trim());

                // Limpiar los textareas
                document.getElementById('redirectUris').parentElement.innerHTML = '';
                document.getElementById('postLogoutRedirectUris').parentElement.innerHTML = '';

                // Crear inputs hidden para cada URI
                redirectUris.forEach(uri => {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'redirectUris';
                    input.value = uri;
                    this.appendChild(input);
                });

                postLogoutUris.forEach(uri => {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'postLogoutRedirectUris';
                    input.value = uri;
                    this.appendChild(input);
                });
            });
        </script>
    `
)
