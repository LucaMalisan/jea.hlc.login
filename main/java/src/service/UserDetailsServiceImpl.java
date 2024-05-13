package src.service;

import io.micrometer.common.util.StringUtils;
import jakarta.json.*;
import json.JsonUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import request.HttpRequestUtil;
import src.config.UserConfig;
import src.model.UserPJO;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private static String accessToken;

    @Value("${security.oauth2.client.id}")
    private String clientId;

    @Value("${security.oauth2.client.secret}")
    private String clientSecret;

    @Value("${security.oauth2.audience}")
    private String audience;

    @Value("${security.oauth2.url}")
    private String oauthUrl;

    @Override
    public UserDetails loadUserByUsername(String email) {

        if (StringUtils.isEmpty(accessToken)) {
            accessToken = this.getAccessToken();
        }

        String content = HttpRequestUtil.createHttpRequestAndGetResponse(
                "http://192.168.56.1:8082/user/rest/all", "GET", accessToken, "");

        JsonArray useList = JsonUtil.getJsonArray("userList", content);
        UserPJO user = null;

        //TODO make string constants somewhere

        for (JsonValue obj : useList) {
            if (JsonUtil.jsonValueToString(obj, "email").equals(email)) {
                user = new UserPJO();
                user.setEmail(JsonUtil.jsonValueToString(obj, "email"));
                user.setPasswordHash(JsonUtil.jsonValueToString(obj, "passwordHash"));
                user.setUserManager(Boolean.parseBoolean(JsonUtil.jsonValueToString(obj, "userManager")));
                user.setAdmin(Boolean.parseBoolean(JsonUtil.jsonValueToString(obj, "admin")));
            }
        }

        if (user == null) {
            throw new UsernameNotFoundException(email);
        }
        return new UserConfig(user);
    }

    private String getAccessToken() {
        String authorization = String.join(":", clientId, clientSecret);
        String dataFormat = "%s=%s&";

        //it is ok that these values aren't defined in a constant, because this calls OAuth.
        //We have no influence on whether OAuth changes these properties anyway.

        String data = String.format(dataFormat, "grant_type", "client_credentials") +
                String.format(dataFormat, "redirect_uri", "urn:ietf:wg:oauth:2.0:oob") +
                String.format(dataFormat, "audience", audience);

        return HttpRequestUtil.createHttpRequestAndGetResponse(oauthUrl, "POST", authorization, data);
    }
}