package src.service;

import cookies.CookieNames;
import cookies.CookieUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.java.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import src.model.AuthorizationDTO;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@Log
public class AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private RedirectStrategy redirectStrategy;
    private final TokenService tokenService;

    public AuthenticationSuccessHandlerImpl(JwtEncoder encoder) {
        this.tokenService = new TokenService(encoder);
        this.redirectStrategy = new DefaultRedirectStrategy();
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication) throws IOException {

        this.handle(request, response, authentication);
    }

    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        Cookie targetUrlCookie = CookieUtils.getCookieByNameOrNull(request, CookieNames.CALLBACK);

        if (targetUrlCookie == null) {
            throw new RuntimeException();
        }

        String targetUrl = targetUrlCookie.getValue();
        String authorizationStr = this.createAuthorizationDTO(request, authentication).toString();
        response.addCookie(new Cookie(CookieNames.AUTHORIZATION_COOKIE, URLEncoder.encode(authorizationStr, StandardCharsets.UTF_8)));
        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    public String token(Authentication authentication) {
        return this.tokenService.generateToken(authentication);
    }

    public AuthorizationDTO createAuthorizationDTO(HttpServletRequest request, Authentication authentication) {
        return AuthorizationDTO.builder()
                .csrf(((CsrfToken) request.getAttribute(CsrfToken.class.getName())).getToken())
                .jwt(this.token(authentication)).build();
    }
}
