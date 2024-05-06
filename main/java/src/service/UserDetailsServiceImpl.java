package src.service;

import io.micrometer.common.util.StringUtils;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import src.config.UserConfig;
import src.model.UserPJO;
import src.utils.HTTPRequestUtil;

import java.io.IOException;
import java.io.StringReader;

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

        String content;
        try {
            content = HTTPRequestUtil.httpRequest("http://192.168.56.1:8082/user/rest/all", "GET", accessToken, "");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        JsonReader reader = Json.createReader(new StringReader(content));
        JsonObject jsonObject = reader.readObject();
        JsonObject embedded = jsonObject.getJsonObject("_embedded");
        UserPJO user = null;

        for (JsonValue obj : embedded.getJsonArray("userList")) {
            if (this.jsonValueToString(obj, "email").equals(email)) {
                user = new UserPJO();
                user.setEmail(this.jsonValueToString(obj, "email"));
                user.setPasswordHash(this.jsonValueToString(obj, "passwordHash"));
                user.setUserManager(Boolean.parseBoolean(this.jsonValueToString(obj, "userManager")));
                user.setAdmin(Boolean.parseBoolean(this.jsonValueToString(obj, "admin")));
            }
        }

        if (user == null) {
            throw new UsernameNotFoundException(email);
        }
        return new UserConfig(user);
    }

    private String jsonValueToString(JsonValue value, String property) {
        return value.asJsonObject().get(property).toString().replace("\"", "");
    }

    private String getAccessToken() {
        String authorization = String.join(":", clientId, clientSecret);
        StringBuilder data = new StringBuilder();
        String dataFormat = "%s=%s&";

        data.append(String.format(dataFormat, "grant_type", "client_credentials"))
                .append(String.format(dataFormat, "redirect_uri", "urn:ietf:wg:oauth:2.0:oob"))
                .append(String.format(dataFormat, "audience", audience));

        String jwt;
        try {
            jwt = HTTPRequestUtil.httpRequest(oauthUrl, "POST", authorization, data.toString());
        } catch (Exception e) {
            throw new InternalError("Failed to get a bearer token");
        }

        return jwt;
    }
}