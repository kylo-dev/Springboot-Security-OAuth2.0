package security.jwt.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import security.jwt.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Boolean existsByUsername(String username);

    Optional<User> findByEmailAndProvider(String email, String provider);
}
