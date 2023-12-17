package security.test.config.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import security.test.config.auth.PrincipalDetails;
import security.test.config.oauth.provider.FacebookUserInfo;
import security.test.config.oauth.provider.GoogleUserInfo;
import security.test.config.oauth.provider.NaverUserInfo;
import security.test.config.oauth.provider.OAuth2UserInfo;
import security.test.model.User;
import security.test.repository.UserRepository;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    /**
     * 구글 로그인 과정
     * 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료
     * Code를 리턴(OAuth-client 라이브러리가 받음) -> AccessToken 요청
     * => userRequest 정보
     * 정보 -> loadUser 함수 호출 -> 구글로부터 회원 프로필
     */

    // 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        // userRequest 확인
        System.out.println("userRequest = " + userRequest);
        System.out.println("getClientRegistration = " + userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인 하는지 알 수 있음
        System.out.println("getAccessToken = " + userRequest.getAccessToken());
        System.out.println("getAttributes = " + super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User = " + oAuth2User.getAttributes());

//        (구글) 회원가입
//        String provider = userRequest.getClientRegistration().getRegistrationId();
//        String providerId = oAuth2User.getAttribute("sub");
//        String username = provider + "_" + providerId;
//        String password = bCryptPasswordEncoder.encode("겟인데어");
//        String email = oAuth2User.getAttribute("email");
//        String role = "ROLE_USER";


        // (구글, 페이스북, 네이버) 회원가입 진행
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        } else{
            System.out.println("구글과 페이스북, 네이버 로그인만 지원합니다.");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User findUser = userRepository.findByUsername(username);
        if(findUser == null) {
            findUser = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(findUser);
        }
        return new PrincipalDetails(findUser, oAuth2User.getAttributes());
    }
}
