package src.handler;

import header.AuthorizationHeaderUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.io.IOException;

/**
 * This class doesn't really serve as an exception handler as defined in the security chain.
 * It catches a request to /login containing the callback parameter (this is not recognized as a call to the login page and generates an exception).
 * It then generates a cookie and redirects to the proper login page without the parameter to continue the algorithm.
 */

public class ParameterInterceptor extends LoginUrlAuthenticationEntryPoint {

    public ParameterInterceptor(String loginFormUrl) {
        super(loginFormUrl);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException {
        String redirect = request.getParameter(AuthorizationHeaderUtils.CALLBACK);

        if (redirect != null) {
            response.addCookie(new Cookie(AuthorizationHeaderUtils.CALLBACK, redirect));
            response.addHeader("Set-Cookie", String.format("%s=%s", AuthorizationHeaderUtils.CALLBACK, redirect));
            response.sendRedirect("http://localhost:8084/auth/login");
        }
    }
}
