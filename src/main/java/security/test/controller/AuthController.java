package security.test.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.test.dto.request.AuthRequest;
import security.test.dto.response.AuthResponse;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    @PostMapping("/signup")
    public void signup(@RequestBody AuthRequest.Register request) {

    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse.Register> login(@RequestBody AuthRequest.Login request) {

        return null;
    }

    @PostMapping("/logout")
    public void logout(HttpServletResponse response) {

    }

    @GetMapping("/reissue-token")
    public ResponseEntity<?> refreshAccessToken(HttpServletRequest request,
        HttpServletResponse response) {

        return null;
    }
}
