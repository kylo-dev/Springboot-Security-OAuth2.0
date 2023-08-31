package security.test.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.test.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {

    User findByUsername(String username);
}
