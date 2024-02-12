package security.jwt.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import security.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
}
