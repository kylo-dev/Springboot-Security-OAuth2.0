package security.jwt.security.auth;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import security.jwt.domain.User;
import security.jwt.service.UserQueryService;

// Security 설정에서 loginProcessingUrl("/login");
// '/login' 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수 실행
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserQueryService userQueryService;

    // Security Session(내부 Authentication(내부 UserDetails)) 구조
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService : 진입");
        Optional<User> user = userQueryService.findByEmail(email);

        if (user.isEmpty()) {
            throw new UsernameNotFoundException(
                "------------------------- 해당 유저를 찾을 수 없습니다. 유저 이메일:  " + email);
        }
        return new PrincipalDetails(user.get());
    }
}
