package security.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import security.jwt.model.Token;
import security.jwt.model.User;
import security.jwt.repository.TokenRepository;
import security.jwt.repository.UserRepository;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenUtil {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;

    @Value("${secret.key}")
    private String SECRET_KEY;

    // Access Token 유효시간
    static final long AccessTokenValidTime = 15 * 60 * 1000L;
    static final long RefreshTokenValidTime = 30 * 60 * 1000L;

    // Access Token 생성
    public String generateAccessToken(String userId) {

        Claims claims = createClaims(userId);
        Date now = new Date();
        SecretKey secretKey = generateKey();

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + AccessTokenValidTime))
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact();
    }

    // Refresh Token 생성
    public String generateRefreshToken(String userId) {
        Claims claims = createClaims(userId);
        Date now = new Date();
        SecretKey secretKey = generateKey();

        String refreshToken = Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + RefreshTokenValidTime))
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact();

        // TODO: 일시적으로 DB에 저장
        tokenRepository.save(Token.builder()
            .refreshToken(refreshToken)
            .build());

        return refreshToken;
    }

    // Token 유효성 검사
    public boolean isVaildToken(String token) {
        try {
            SecretKey secretKey = generateKey();
            Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);

            return claims.getBody()
                .getExpiration()
                .after(new Date());
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
            throw e;
        } catch (Exception e) {
            // TODO: Exception 처리로 변경
            return false;
        }
    }

    // Access Token에서 UserId 파싱
    public String getUserIdFromToken(String token) {
        SecretKey secretKey = generateKey();
        String userId = Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(token)
            .getBody().getSubject();

        log.info("---------------------------TokenUtil.getUserIdFromToken: " + userId);
        return userId;
    }

    // Access Token 재발행
    public String refreshAccessToken(String refreshToken) {
        String userId = getUserIdFromToken(refreshToken);

        return generateAccessToken(userId);
    }

    // Access Token을 Header에서 추출하는 메서드
    public String getJWTTokenFromHeader(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null) {
            return authorizationHeader;
        }
        return null;
    }

    // Token 인증 과정
    public void getAuthenticationFromToken(String accessToken) {

        User loginUser = getUserFromToken(accessToken);
        setContextHolder(accessToken, loginUser);
    }

    private void setContextHolder(String token, User loginUser) {

        List<GrantedAuthority> authorities = getAuthoritiesFromMember(loginUser);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
            loginUser, token, authorities);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

    // 사용자 권한 가져오기
    private List<GrantedAuthority> getAuthoritiesFromMember(User user) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        String role = user.getRole();
        if (role != null) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        return authorities;
    }

    private User getUserFromToken(String token) {

        return userRepository.findById(Long.valueOf(getUserIdFromToken(token))).get();
    }

    // JWT Key 생성
    private SecretKey generateKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    // JWT Claims 생성 (소셜 로그인의 email 저장)
    private Claims createClaims(String id) {
        return Jwts.claims().setSubject(id);
    }
}
