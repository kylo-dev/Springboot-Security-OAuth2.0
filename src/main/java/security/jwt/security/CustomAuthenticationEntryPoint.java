package security.jwt.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import security.jwt.exception.ErrorType;

// 사용자가 인증되지 않은 경우(인증 예외가 발생한 경우)에 실행
@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException) throws IOException, ServletException {

        ErrorType errorType = null;
        String requestURI = request.getRequestURI();

        if (authException instanceof UsernameNotFoundException) {
            setResponse(response, ErrorType.CHECK_ID_AGAIN);
        } else if (authException instanceof BadCredentialsException) {
            setResponse(response, ErrorType.CHECK_PASSWORD_AGAIN);
        } else if (authException instanceof InsufficientAuthenticationException) {
            setResponse(response, ErrorType.ACCESS_TOKEN_EXPIRED);
        }
    }

    private void setResponse(HttpServletResponse response, ErrorType errorType) throws IOException {

        response.setContentType("application/json;charset=UTF-8");

        int status = Integer.parseInt(String.valueOf(errorType.getStatus()).substring(0, 3));
        response.setStatus(status);

        response.getWriter().println(
            "{\"status\" : \"" + errorType.getStatus() + "\"," +
                "\"errorCode\" : \"" + errorType.getErrorCode() + "\"," +
                " \"message\" : \"" + errorType.getMessage() +
                "\"}");
    }
}
