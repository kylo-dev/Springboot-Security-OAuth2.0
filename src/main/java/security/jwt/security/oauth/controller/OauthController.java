package security.jwt.security.oauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class OauthController {

    @GetMapping("/google")
    public void googleLogin() {
    }

    @GetMapping("/facebook")
    public void facebookLogin() {
    }

    @GetMapping("/naver")
    public void naverLogin() {
    }
}
