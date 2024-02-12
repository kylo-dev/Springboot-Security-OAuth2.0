package security.test.config.oauth.userinfo;

public interface OAuth2UserInfo {

    String getProviderId();

    String getProvider();  // google, facebook

    String getEmail();

    String getName();
}
