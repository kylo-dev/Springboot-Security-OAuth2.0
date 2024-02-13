package security.jwt.util;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    public void create(String value, HttpServletResponse response) {

        ResponseCookie responseCookie = ResponseCookie.from("refreshToken", value)
            .path("/")
            .secure(true)
            .sameSite("None")
            .httpOnly(false)
            .maxAge(Integer.MAX_VALUE)
            .build();

        response.addHeader("Set-Cookie", responseCookie.toString());
    }

    public void delete(String value, HttpServletResponse response) {

        ResponseCookie responseCookie = ResponseCookie.from("refreshToken", value)
            .path("/")
            .secure(true)
            .sameSite("None")
            .httpOnly(false)
            .maxAge(0)
            .build();

        response.addHeader("Set-Cookie", responseCookie.toString());
    }
}
