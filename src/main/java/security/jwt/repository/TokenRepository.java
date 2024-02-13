package security.jwt.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import security.jwt.domain.Token;

public interface TokenRepository extends JpaRepository<Token, Long> {

    Optional<Token> findByRefreshToken(String token);
}
