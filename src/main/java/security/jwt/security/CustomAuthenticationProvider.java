package security.jwt.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import security.jwt.security.auth.PrincipalDetails;
import security.jwt.security.auth.PrincipalDetailsService;

@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final PrincipalDetailsService principalDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // 사용자 인증 처리
    // Authentication 객체를 통해 사용자의 아디이, 비밀번호 파싱
    @Override
    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {

        final UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;

        // AuthenticationFilter에서 생성된 토큰으로부터 아이디와 비밀번호 조회
        final String email = token.getName();
        final String password = (String) token.getCredentials();

        // PrincipalDetailService를 통해 DB에서 아이디로 사용자 조회
        final PrincipalDetails principalDetails;
        try {
            principalDetails = (PrincipalDetails) principalDetailsService.loadUserByUsername(
                email);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        if (!bCryptPasswordEncoder.matches(password, principalDetails.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }

        return new UsernamePasswordAuthenticationToken(principalDetails, password,
            principalDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
