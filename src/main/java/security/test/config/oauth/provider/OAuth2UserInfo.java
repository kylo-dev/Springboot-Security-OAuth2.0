package security.test.config.oauth.provider;

public interface OAuth2UserInfo {

    String getProviderId();
    String getProvider();  // google, facebook
    String getEmail();
    String getName();
}
