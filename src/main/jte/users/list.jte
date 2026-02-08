@import java.util.List
@import com.app.oauth2server.entities.Users
@param List<Users> users

@template.layout(
    title = "Gestión de Usuarios",
    content = @`
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h2>Usuarios</h2>
                <div>
                    <a href="/authorities" class="btn btn-secondary" style="margin-right: 0.5rem;">Authorities</a>
                    <a href="/users/new" class="btn">Nuevo Usuario</a>
                </div>
            </div>

            @if(users.isEmpty())
                <p>No hay usuarios registrados. <a href="/users/new">Crear el primero</a></p>
            @else
                <table>
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Roles</th>
                            <th>Estado</th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        @for(Users user : users)
                            <tr>
                                <td>${user.getUsername()}</td>
                                <td>${String.join(", ", user.getRoles())}</td>
                                <td>
                                    @if(user.isEnabled())
                                        <span style="color: green;">Activo</span>
                                    @else
                                        <span style="color: red;">Inactivo</span>
                                    @endif
                                </td>
                                <td>
                                    <a href="/users/edit/${user.getId()}" class="btn btn-secondary">Editar</a>
                                    <a href="/users/delete/${user.getId()}"
                                       class="btn btn-danger"
                                       onclick="return confirm('¿Estás seguro de eliminar este usuario?')">Eliminar</a>
                                </td>
                            </tr>
                        @endfor
                    </tbody>
                </table>
            @endif
        </div>
    `
)
