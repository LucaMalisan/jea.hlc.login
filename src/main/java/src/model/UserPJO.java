package src.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserPJO {

  //E-Mail is taken as username
  private String email;
  private String passwordHash;
  private boolean admin;
  private boolean userManager;
}
