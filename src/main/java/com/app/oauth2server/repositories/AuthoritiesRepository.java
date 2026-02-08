package com.app.oauth2server.repositories;

import com.app.oauth2server.entities.Authorities;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AuthoritiesRepository extends ReactiveMongoRepository<Authorities, String> {
    Mono<Authorities> findByClientId(String clientId);
}
