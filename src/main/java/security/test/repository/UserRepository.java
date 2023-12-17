package security.test.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.test.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);
    Boolean existsByUsername(String username);
}
