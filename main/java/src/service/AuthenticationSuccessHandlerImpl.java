package src.service;

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
import java.util.Arrays;

@Component
@Log
public class AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private RedirectStrategy redirectStrategy;
    private final JwtEncoder encoder;
    private final TokenService tokenService;

    public AuthenticationSuccessHandlerImpl(JwtEncoder encoder) {
        this.encoder = encoder;
        this.tokenService = new TokenService(encoder);
        this.redirectStrategy = new DefaultRedirectStrategy();
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication) throws IOException {

        this.handle(request, response, authentication);
    }

    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = Arrays.stream(request.getCookies())
                .filter(e -> e.getName().equals("callback"))
                .map(Cookie::getValue)
                .findFirst()
                .orElseThrow(NullPointerException::new);
        String authorizationStr = this.createAuthorizationDTO(request, authentication).toString().replace(",", "%2C");
        response.addCookie(new Cookie("authorization", URLEncoder.encode(authorizationStr, StandardCharsets.UTF_8)));
        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    public String token(Authentication authentication) {
        log.info("Token requested for user: " + authentication.getName());
        String token = this.tokenService.generateToken(authentication);
        log.info("Token granted: " + token);
        return token;
    }

    public AuthorizationDTO createAuthorizationDTO(HttpServletRequest request, Authentication authentication) {
        return AuthorizationDTO.builder()
                .userName(authentication.getName())
                .userManager(authentication.getAuthorities().contains(new SimpleGrantedAuthority("user_manager")))
                .admin(authentication.getAuthorities().contains(new SimpleGrantedAuthority("admin")))
                .csrf(((CsrfToken) request.getAttribute(CsrfToken.class.getName())).getToken())
                .jwt(this.token(authentication)).build();
    }
}
