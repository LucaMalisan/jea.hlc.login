package src.model;

import cookies.AuthorizationCookieFields;
import cookies.CookieUtils;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class AuthorizationDTO {
    private String csrf;
    private String jwt;

    @Override
    public String toString() {
        return CookieUtils.authorizationCookieFormat(AuthorizationCookieFields.CSRF, csrf) +
                CookieUtils.authorizationCookieFormat(AuthorizationCookieFields.JWT, jwt);
    }
}
