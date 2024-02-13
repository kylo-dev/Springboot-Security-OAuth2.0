package security.jwt.security.oauth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import security.jwt.domain.User;
import security.jwt.repository.TokenRepository;
import security.jwt.repository.UserRepository;
import security.jwt.security.auth.PrincipalDetails;
import security.jwt.security.oauth.userinfo.FacebookUserInfo;
import security.jwt.security.oauth.userinfo.GoogleUserInfo;
import security.jwt.security.oauth.userinfo.NaverUserInfo;
import security.jwt.util.TokenUtil;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final TokenUtil tokenUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException, ServletException {

        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        String provider = principal.getUser().getProvider();
        Map<String, Object> attributes = principal.getAttributes();
        String email = null;

        if (provider.equals("naver")) {
            NaverUserInfo naverUserInfo = new NaverUserInfo((Map) attributes.get("response"));
            email = naverUserInfo.getEmail();
        } else if (provider.equals("google")) {
            GoogleUserInfo googleUserInfo = new GoogleUserInfo(attributes);
            email = googleUserInfo.getEmail();
        } else if (provider.equals("facebook")) {
            FacebookUserInfo facebookUserInfo = new FacebookUserInfo(attributes);
            email = facebookUserInfo.getEmail();
        }

        log.info("------------------------- 소셜 로그인 성공: " + email + "소셜 타입: " + provider);

        Optional<User> user = userRepository.findByEmailAndProvider(email, provider);
        String userId = String.valueOf(user.get().getId());

        // 인증이 성공했을 때, Access token, Refresh token 발급
        String accessToken = tokenUtil.generateAccessToken(userId);
        response.setHeader("Authorization", accessToken);

        log.info("--------------------------------- access token 생성 : " + accessToken);
        // 리프레시 토큰을 Redis 에 저장
//        if (redisUtil.getData(userId) == null) {
//            String refreshToken = tokenUtil.generateRefreshToken(userId);
//            // 리프레시 토큰은 쿠키에 담아서 응답으로 보냄
//            cookieUtil.create(refreshToken, response);
//        }
        response.sendRedirect("/");
    }
}
