package security.test.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;
import security.test.util.TokenUtil;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenUtil tokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        if (isPublicURI(requestURI)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Header에서 Jwt 추출
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && isBearer(authorizationHeader)) {
            String jwtToken = authorizationHeader.substring(7);

            // token 유효성 검증
            tokenUtil.isVaildToken(jwtToken);

            // token을 통해 User 정보 인증
            tokenUtil.getAuthenticationFromToken(jwtToken);
        }

        filterChain.doFilter(request, response);
    }

    // 검증이 필요없는 URI 작성
    private boolean isPublicURI(String requestURI) {
        return requestURI.startsWith("/auth/**") ||
            requestURI.startsWith("/oauth") ||
            requestURI.startsWith("/swagger-ui") ||
            requestURI.startsWith("/login") ||
            requestURI.startsWith("/favicon.ico");
    }

    // "Bearer "로 시작하는지 확인
    private boolean isBearer(String authorizationHeader) {
        return authorizationHeader.startsWith("Bearer ");
    }
}

