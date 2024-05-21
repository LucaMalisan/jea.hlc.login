package src.service;

import cookies.CookieUtils;
import header.AuthorizationHeaderUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jwt.JwtRestUtil;
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

    @Value("${security.oauth2.client.id}")
    private String clientId;

    @Value("${security.oauth2.client.secret}")
    private String clientSecret;

    @Value("${security.oauth2.audience}")
    private String audience;

    @Value("${security.oauth2.url}")
    private String oauthUrl;

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

        String id = JwtRestUtil.generateClientId(request);
        String targetUrl = targetUrlCookie.getValue();
        String authorizationStr = this.createAuthorizationDTO(request, authentication).toString();

        //Possibility 1 for modules that support using cookies (e.g. Spring)
        response.addCookie(new Cookie(CookieUtils.AUTHORIZATION_COOKIE, URLEncoder.encode(authorizationStr, StandardCharsets.UTF_8)));

        //Possibility 2 for modules with bad cookie support (e.g. Jakarta EE)
        HttpRequestUtil.createHttpRequestAndGetResponse(
                JwtRestUtil.generateAuthRestURI(targetUrl),
                "POST",
                URLEncoder.encode(authorizationStr, StandardCharsets.UTF_8),
                Map.of("id", id, HeaderFields.AUTHORIZATION, this.getAccessToken()));

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
        String authorization = String.join(":", clientId, clientSecret);
        String dataFormat = "%s=%s&";

        //it is ok that these values aren't defined in a constant, because this calls OAuth.
        //We have no influence on whether OAuth changes these properties anyway.

        String data = String.format(dataFormat, "grant_type", "client_credentials") +
                String.format(dataFormat, "redirect_uri", "urn:ietf:wg:oauth:2.0:oob") +
                String.format(dataFormat, "audience", audience);

        return HttpRequestUtil.createHttpRequestAndGetResponse(oauthUrl, "POST", data, Map.of(HeaderFields.AUTHORIZATION, authorization));
    }

}
