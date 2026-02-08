package com.app.oauth2server.entities;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Builder
@Document(collection = "authorities")
public class Authorities {
    @Id
    private String id;

}
