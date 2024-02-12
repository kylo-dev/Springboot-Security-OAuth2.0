package security.test.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.test.model.Token;

public interface TokenRepository extends JpaRepository<Token, Long> {

}
