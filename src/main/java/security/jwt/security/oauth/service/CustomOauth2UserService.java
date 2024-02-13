package security.jwt.security.oauth.service;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import security.jwt.domain.User;
import security.jwt.security.auth.PrincipalDetails;
import security.jwt.security.oauth.userinfo.OAuth2UserInfo;
import security.jwt.security.oauth.userinfo.OAuthUserInfoFactory;
import security.jwt.service.UserCommandService;
import security.jwt.service.UserQueryService;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOauth2UserService extends DefaultOAuth2UserService {

    private final @Lazy BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserQueryService userQueryService;
    private final UserCommandService userCommandService;

    /**
     * 구글 로그인 과정 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 Code를 리턴(OAuth-client 라이브러리가 받음) -> AccessToken
     * 요청 => userRequest 정보 정보 -> loadUser 함수 호출 -> 구글로부터 회원 프로필, 이메일 정보 가져오기 !!
     */

    // 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.

    // * 오버로딩 한 이유
    // 1. Oauth로 로그인한 경우도 PrincipalDetails로 정보를 받아오기 위함
    // 2. Oauth로 로그인했을 때 강제로 웹 사이트에서 회원가입을 진행하기 위함
    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(request);
        log.info("------------------ getAttributes : {}", oAuth2User.getAttributes());

        String provider = request.getClientRegistration().getRegistrationId();

        // 어떤 소셜 로그인인지 구분
        OAuth2UserInfo oAuthUserInfo = OAuthUserInfoFactory.getOAuthUserInfo(provider,
            oAuth2User.getAttributes());

        Optional<User> user = userQueryService.findByEmailAndProvider(oAuthUserInfo.getEmail(),
            provider);

        if (user.isEmpty()) {
            User newUser = User.builder()
                .username(oAuthUserInfo.getName())
                .email(oAuthUserInfo.getEmail())
                .provider(provider)
                .providerId(oAuthUserInfo.getProviderId())
                .role("USER")
                .password(bCryptPasswordEncoder.encode("oauth2"))
                .build();

            userCommandService.save(newUser);

            return new PrincipalDetails(newUser, oAuth2User.getAttributes());
        }

        return new PrincipalDetails(user.get(), oAuth2User.getAttributes());
    }

}
