package security.test.dto.response;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

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
}
