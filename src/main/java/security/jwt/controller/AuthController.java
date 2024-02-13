package security.jwt.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.jwt.dto.request.AuthRequest;
import security.jwt.dto.response.AuthResponse;
import security.jwt.service.AuthService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public void signup(@RequestBody AuthRequest.Register request) {
        authService.register(request);
    }

    @PostMapping("/login")
    public AuthResponse.Login login(@RequestBody AuthRequest.Login request,
        HttpServletResponse response) {

        return authService.login(request, response);
    }

    @PostMapping("/logout")
    public void logout(HttpServletResponse response) {
        authService.logout(response);
    }

    @GetMapping("/reissue-token")
    public ResponseEntity<?> refreshAccessToken(HttpServletRequest request,
        HttpServletResponse response) {

        return null;
    }
}
