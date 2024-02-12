package security.test.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import security.test.dto.request.AuthRequest;
import security.test.dto.response.AuthResponse;

@RestController
@RequiredArgsConstructor
public class AuthController {

    @PostMapping("/auth/signup")
    public void signup(@RequestBody AuthRequest.Register request) {

    }

    @PostMapping("/auth/login")
    public ResponseEntity<AuthResponse.Register> login(@RequestBody AuthRequest.Login request) {

        return null;
    }

    @PostMapping("/auth/logout")
    public void logout(HttpServletResponse response) {

    }
}
