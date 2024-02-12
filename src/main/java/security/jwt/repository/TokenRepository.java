package security.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.jwt.model.Token;

public interface TokenRepository extends JpaRepository<Token, Long> {

}
