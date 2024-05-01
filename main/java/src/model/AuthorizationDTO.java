package src.model;

import lombok.Builder;
import lombok.ToString;

@Builder
@ToString
public class AuthorizationDTO {

    public String userName;
    public boolean userManager;
    public boolean admin;
    public String csrf;
    public String jwt;
}
