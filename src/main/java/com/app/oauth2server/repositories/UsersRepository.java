package com.app.oauth2server.repositories;

import com.app.oauth2server.entities.Users;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface UsersRepository extends ReactiveMongoRepository<Users, String> {
    Mono<Users> findByUsername(String username);
}
