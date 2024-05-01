package src.model;

import lombok.Builder;
import lombok.ToString;

@Builder
public class AuthorizationDTO {
    public String csrf;
    public String jwt;

    @Override
    public String toString() {
        return "csrf:'" + csrf + ", jwt:'" + jwt;
    }
}
