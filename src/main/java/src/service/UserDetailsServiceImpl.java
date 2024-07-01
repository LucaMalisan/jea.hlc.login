package src.service;

import io.micrometer.common.util.StringUtils;
import jakarta.json.*;
import json.JsonUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import request.HeaderFields;
import request.HttpRequestUtil;
import src.config.UserConfig;
import src.model.UserPJO;

import java.io.StringReader;
import java.util.Map;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private static String accessToken;

    @Override
    public UserDetails loadUserByUsername(String email) {

        if (StringUtils.isEmpty(accessToken)) {
            accessToken = this.getAccessToken();
        }

        String content = HttpRequestUtil.createHttpRequestAndGetResponse(
                "http://host.docker.internal:8082/user/rest/all", "GET", "", Map.of(HeaderFields.AUTHORIZATION, accessToken));

        JsonReader reader = Json.createReader(new StringReader(content));
        JsonArray userList = reader.readArray();
        UserPJO user = null;

        //TODO make string constants somewhere

        for (JsonValue obj : userList) {
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