@import java.util.List
@import com.app.oauth2server.entities.Authorities
@param List<Authorities> authorities

@template.layout(
    title = "Gestión de Authorities (OAuth2 Clients)",
    content = @`
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h2>Authorities (OAuth2 Clients)</h2>
                <div>
                    <a href="/users" class="btn btn-secondary" style="margin-right: 0.5rem;">Usuarios</a>
                    <a href="/authorities/new" class="btn">Nueva Authority</a>
                </div>
            </div>

            @if(authorities.isEmpty())
                <p>No hay authorities registradas. <a href="/authorities/new">Crear la primera</a></p>
            @else
                <table>
                    <thead>
                        <tr>
                            <th>Client ID</th>
                            <th>Auth Methods</th>
                            <th>Grant Types</th>
                            <th>Scopes</th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        @for(Authorities authority : authorities)
                            <tr>
                                <td>${authority.getClientId()}</td>
                                <td>${String.join(", ", authority.getClientAuthenticationMethods())}</td>
                                <td>${String.join(", ", authority.getAuthorizationGrantTypes())}</td>
                                <td>${String.join(", ", authority.getScopes())}</td>
                                <td>
                                    <a href="/authorities/edit/${authority.getId()}" class="btn btn-secondary">Editar</a>
                                    <a href="/authorities/delete/${authority.getId()}"
                                       class="btn btn-danger"
                                       onclick="return confirm('¿Estás seguro de eliminar esta authority?')">Eliminar</a>
                                </td>
                            </tr>
                        @endfor
                    </tbody>
                </table>
            @endif
        </div>
    `
)
