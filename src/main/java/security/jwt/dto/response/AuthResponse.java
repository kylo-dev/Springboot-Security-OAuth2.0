package security.jwt.dto.response;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import security.jwt.domain.User;

public class AuthResponse {

    @Builder
    @Getter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Register {

        private Long userId;
        private LocalDateTime createdAt;
    }

    public static Register toRegister(Long userId) {

        return Register.builder()
            .userId(userId)
            .createdAt(LocalDateTime.now())
            .build();
    }

    @Builder
    @Getter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Login {

        private Long userId;
        private String email;
        private String provider;
        private LocalDateTime createdAt;
    }

    public static Login toLogin(User user) {

        return Login.builder()
            .userId(user.getId())
            .email(user.getEmail())
            .provider(user.getProvider())
            .createdAt(LocalDateTime.now())
            .build();
    }
}
