package security.test.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import security.test.model.User;
import security.test.repository.UserRepository;
import security.test.security.auth.PrincipalDetails;

// Security 설정에서 loginProcessingUrl("/login");
// '/login' 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수 실행
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // Security Session(내부 Authentication(내부 UserDetails)) 구조
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService : 진입");
        User findUser = userRepository.findByUsername(username).orElseThrow(
            () -> new UsernameNotFoundException("존재하지 않는 회원입니다.")
        );
        return new PrincipalDetails(findUser);
    }
}
