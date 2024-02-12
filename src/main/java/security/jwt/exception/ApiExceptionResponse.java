package security.jwt.exception;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Schema(description = "API 응답 에러 DTO")
public class ApiExceptionResponse {

    @Schema(description = "상태 코드")
    private int status;

    @Schema(description = "에러 코드")
    private String errorCode;

    @Schema(description = "에러 메시지")
    private String message;
}
