package security.jwt.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import security.jwt.dto.request.AuthRequest;

// 사용자가 제공한 아이디와 비밀번호를 사용하여 사용자를 인증
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // AuthenticationManager 사용자 인증 수행
    public CustomAuthenticationFilter(final AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    // 클라이언트로부터 받은 요청을 검증
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws AuthenticationException {

        final UsernamePasswordAuthenticationToken authenticationToken;

        try {
            final AuthRequest.Login loginRequest = new ObjectMapper().readValue(
                request.getInputStream(), AuthRequest.Login.class);

            log.info("------------------------- 사용자 아이디: " + loginRequest.getEmail() + " 비밀번호: "
                + loginRequest.getPassword());

            authenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequest.getEmail(), loginRequest.getPassword());
        } catch (IOException e) {
            throw new org.springframework.security.authentication.AuthenticationServiceException(
                "Failed to parse authentication request body", e);
        }

        // 요청된 정보를 바탕으로 UsernamePasswordAuthenticationToken 설정
        setDetails(request, authenticationToken);

        return this.getAuthenticationManager().authenticate(authenticationToken);
    }
}
