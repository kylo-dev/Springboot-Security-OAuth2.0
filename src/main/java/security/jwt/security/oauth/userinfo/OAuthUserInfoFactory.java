package security.jwt.security.oauth.userinfo;

import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OAuthUserInfoFactory {

    public static OAuth2UserInfo getOAuthUserInfo(String provider, Map<String, Object> attributes) {

        if (provider.equals("google")) {
            log.info("----------------------------- 구글 로그인 요청");
            return new GoogleUserInfo(attributes);
        } else if (provider.equals("naver")) {
            log.info("----------------------------- 네이버 로그인 요청");
            return new NaverUserInfo((Map) attributes.get("response"));
        } else if (provider.equals("facebook")) {
            log.info("----------------------------- 페이스북 로그인 요청");
            return new FacebookUserInfo(attributes);
        }

        return null;
    }
}