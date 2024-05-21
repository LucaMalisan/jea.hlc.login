package src.handler;

import cookies.CookieUtils;
import header.AuthorizationHeaderUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.io.IOException;

public class ParameterInterceptor extends LoginUrlAuthenticationEntryPoint {

    public ParameterInterceptor(String loginFormUrl) {
        super(loginFormUrl);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException {
        RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

        Cookie previouslySavedCookie = CookieUtils.getCookieByNameOrNull(request, AuthorizationHeaderUtils.CALLBACK);

        if (previouslySavedCookie != null && !previouslySavedCookie.getValue().isEmpty()) {
            response.addCookie(new Cookie(AuthorizationHeaderUtils.CALLBACK, previouslySavedCookie.getValue()));
        } else {
            String redirect = request.getParameter(AuthorizationHeaderUtils.CALLBACK);

            if(redirect != null) {
                response.addCookie(new Cookie(AuthorizationHeaderUtils.CALLBACK, redirect));
            }
        }

        redirectStrategy.sendRedirect(request, response, "/login");
    }
}
