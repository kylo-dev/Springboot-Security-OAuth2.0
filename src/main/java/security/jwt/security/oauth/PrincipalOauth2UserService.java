package security.jwt.security.oauth;

import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import security.jwt.security.auth.PrincipalDetails;
import security.jwt.security.oauth.userinfo.FacebookUserInfo;
import security.jwt.security.oauth.userinfo.GoogleUserInfo;
import security.jwt.security.oauth.userinfo.NaverUserInfo;
import security.jwt.security.oauth.userinfo.OAuth2UserInfo;
import security.jwt.model.User;
import security.jwt.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

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
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        // userRequest 확인
        System.out.println("userRequest = " + userRequest);
        System.out.println("getClientRegistration = "
            + userRequest.getClientRegistration()); // registrationId로 어떤 oauth로 로그인 하는지 알 수 있음
        System.out.println("getAccessToken = " + userRequest.getAccessToken());
        System.out.println("getAttributes = " + super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User = " + oAuth2User.getAttributes());  // 주요 정보가 저장되어 있음

        //== oauth 정보를 바탕으로 회원가입 진행 ==//
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = getOAuth2UserInfo(registrationId,
            oAuth2User.getAttributes());

        if (oAuth2UserInfo == null) {
            System.out.println("구글, 페이스북, 네이버 로그인만 제공합니다.");
            throw new OAuth2AuthenticationException(new OAuth2Error("unsupported_provider"));
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2UserInfo.getEmail();
        String role = "USER";

        Optional<User> optionalUser = userRepository.findByUsername(username);
        User user = optionalUser.orElseGet(() -> userRepository.save(
            User.builder()
                .username(username)
                .password(password)
                .email(email)
                .role(role)
                .provider(provider)
                .providerId(providerId)
                .build()
        ));
        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }

    private OAuth2UserInfo getOAuth2UserInfo(String registrationId,
        Map<String, Object> attributes) {
        return switch (registrationId) {
            case "google" -> {
                System.out.println("구글 로그인 요청");
                yield new GoogleUserInfo(attributes);
            }
            case "facebook" -> {
                System.out.println("페이스북 로그인 요청");
                yield new FacebookUserInfo(attributes);
            }
            case "naver" -> {
                System.out.println("네이버 로그인 요청");
                yield new NaverUserInfo((Map) attributes.get("response"));
            }
            default -> null;
        };
    }
}
