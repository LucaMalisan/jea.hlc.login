package src.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "_user")
@Getter
@Setter
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_seq_gen")
  @SequenceGenerator(name = "user_seq_gen", sequenceName = "_user_id_seq", allocationSize = 1)
  @Column(name = "id")
  private long id;

  @Column(name = "firstname")
  private String firstName;

  @Column(name = "name")
  private String name;

  //E-Mail is taken as username
  @Column(name = "email")
  private String email;

  @Column(name = "passwordhash")
  private String passwordHash;

  @Column(name = "admin")
  private boolean admin;

  @Column(name = "usermanager")
  private boolean userManager;


}
