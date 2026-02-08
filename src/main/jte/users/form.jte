@import com.app.oauth2server.entities.Users
@param Users user
@param boolean isNew

@template.layout(
    title = isNew ? "Nuevo Usuario" : "Editar Usuario",
    content = @`
        <div class="card">
            <h2>${isNew ? "Nuevo Usuario" : "Editar Usuario"}</h2>

            <form action="/users/save" method="post">
                @if(!isNew && user.getId() != null)
                    <input type="hidden" name="id" value="${user.getId()}">
                @endif

                <div class="form-group">
                    <label for="username">Username *</label>
                    <input type="text" id="username" name="username"
                           value="${user.getUsername() != null ? user.getUsername() : ""}"
                           required
                           ${!isNew ? "readonly style=\"background-color: #f0f0f0;\"" : ""}>
                    @if(!isNew)
                        <small style="color: #666;">El username no se puede cambiar</small>
                    @endif
                </div>

                <div class="form-group">
                    <label for="password">Password ${isNew ? "*" : "(dejar vacío para no cambiar)"}</label>
                    <input type="password" id="password" name="password"
                           ${isNew ? "required" : ""}>
                    <small style="color: #666;">La contraseña será encriptada con BCrypt automáticamente</small>
                </div>

                <div class="form-group">
                    <label>Roles *</label>
                    <div>
                        <label>
                            <input type="checkbox" name="roles" value="USER"
                                   ${user.getRoles() != null && user.getRoles().contains("USER") ? "checked" : ""}>
                            USER
                        </label>
                    </div>
                    <div>
                        <label>
                            <input type="checkbox" name="roles" value="ADMIN"
                                   ${user.getRoles() != null && user.getRoles().contains("ADMIN") ? "checked" : ""}>
                            ADMIN
                        </label>
                    </div>
                </div>

                <div class="form-group">
                    <label>
                        <input type="checkbox" name="enabled" value="true"
                               ${user.isEnabled() ? "checked" : ""}>
                        Usuario Activo
                    </label>
                </div>

                <div class="actions">
                    <button type="submit" class="btn">Guardar</button>
                    <a href="/users" class="btn btn-secondary">Cancelar</a>
                </div>
            </form>
        </div>
    `
)
