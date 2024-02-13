package security.jwt.service;

import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import security.jwt.domain.User;
import security.jwt.dto.request.AuthRequest;
import security.jwt.dto.response.AuthResponse;
import security.jwt.exception.ApiException;
import security.jwt.exception.ErrorType;
import security.jwt.util.CookieUtil;
import security.jwt.util.RedisUtil;
import security.jwt.util.TokenUtil;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final UserQueryService userQueryService;
    private final UserCommandService userCommandService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final TokenUtil tokenUtil;
    private final RedisUtil redisUtil;
    private final CookieUtil cookieUtil;
    private final AuthenticationManager authenticationManager;

    // 회원가입
    @Transactional
    public void register(AuthRequest.Register request) throws ApiException {

        Optional<User> user = userQueryService.findByEmail(request.getEmail());

        if (user.isPresent()) {
            throw new ApiException(ErrorType.ALREADY_EXIST_EMAIL);
        }

        if (request.getEmail() == null || request.getPassword() == null
            || request.getUsername() == null) {
            throw new ApiException(ErrorType.NULL_VALUE_EXIST);
        }

        User newUser = User.builder()
            .username(request.getUsername())
            .email(request.getEmail())
            .password(bCryptPasswordEncoder.encode(request.getPassword()))
            .role("USER")
            .provider("local")
            .build();
        userCommandService.save(newUser);
    }

    // 로그인
    @Transactional
    public AuthResponse.Login login(AuthRequest.Login request, HttpServletResponse response) {

        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getEmail(), request.getPassword()
            )
        );

        User user = userQueryService.findByEmailAndProvider(request.getEmail(), "local")
            .orElseThrow(() -> new ApiException(ErrorType.USER_NOT_FOUND));
        String userId = String.valueOf(user.getId());

        // 인증 성공 시
        String accessToken = tokenUtil.generateAccessToken(userId);
        response.setHeader("Authorization", accessToken);

        // 리프레쉬 토큰 설정
        if (redisUtil.getData(userId) == null) {
            String refreshToken = tokenUtil.generateRefreshToken(userId);
            cookieUtil.create(refreshToken, response);
        } else {
            String refreshToken = redisUtil.getData(userId);
            cookieUtil.create(refreshToken, response);
        }

        return AuthResponse.toLogin(user);
    }

    @Transactional
    public void logout(HttpServletResponse response) {

        response.setHeader("Authorization", "");
        cookieUtil.delete("", response);
    }
}
