package src.service;

import cookies.CookieUtils;
import header.AuthorizationHeaderUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import request.HeaderFields;
import request.HttpRequestUtil;
import src.model.AuthorizationDTO;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
@Log
public class AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final TokenService tokenService;

    public AuthenticationSuccessHandlerImpl(JwtEncoder encoder) {
        this.tokenService = new TokenService(encoder);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication) throws IOException {

        this.handle(request, response, authentication);
    }

    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        Cookie targetUrlCookie = CookieUtils.getCookieByNameOrNull(request, AuthorizationHeaderUtils.CALLBACK);

        if (targetUrlCookie == null) {
            throw new RuntimeException();
        }

        String targetUrl = targetUrlCookie.getValue();
        String authorizationStr = this.createAuthorizationDTO(request, authentication).toString();
        Cookie authorizationCookie = new Cookie(CookieUtils.AUTHORIZATION_COOKIE, URLEncoder.encode(authorizationStr, StandardCharsets.UTF_8));
        authorizationCookie.setHttpOnly(true);
        authorizationCookie.setPath("/");
        response.addCookie(authorizationCookie);

        //remove target url cookie
        targetUrlCookie.setMaxAge(0);
        response.addCookie(targetUrlCookie);

        response.sendRedirect(targetUrl);
    }

    public String token(Authentication authentication) {
        return this.tokenService.generateToken(authentication);
    }

    public AuthorizationDTO createAuthorizationDTO(HttpServletRequest request, Authentication authentication) {
        return AuthorizationDTO.builder()
                .csrf(((CsrfToken) request.getAttribute(CsrfToken.class.getName())).getToken())
                .jwt(this.token(authentication)).build();
    }

    private String getAccessToken() {
        String authorization = String.join(":", System.getenv("CLIENT_ID"), System.getenv("CLIENT_SECRET"));
        String dataFormat = "%s=%s&";

        //it is ok that these values aren't defined in a constant, because this calls OAuth.
        //We have no influence on whether OAuth changes these properties anyway.

        String data = String.format(dataFormat, "grant_type", "client_credentials") +
                String.format(dataFormat, "redirect_uri", "urn:ietf:wg:oauth:2.0:oob") +
                String.format(dataFormat, "audience", System.getenv("AUDIENCE"));

        return HttpRequestUtil.createHttpRequestAndGetResponse(System.getenv("OAUTH_URL"), "POST", data, Map.of(HeaderFields.AUTHORIZATION, authorization));
    }

}
