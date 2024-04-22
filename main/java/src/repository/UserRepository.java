package src.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import src.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findUserByEmail(String userName);
}
