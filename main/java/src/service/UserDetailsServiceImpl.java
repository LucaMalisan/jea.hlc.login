package src.service;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import src.config.UserConfig;
import src.model.UserPJO;
import src.utils.HTTPRequestUtil;

import java.io.IOException;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String email) {

        Map<String, String> articleMap = new LinkedHashMap<>();

        String content = null;
        try {
            content = HTTPRequestUtil.httpRequest("http://192.168.56.1:8082/user/rest/all", "GET");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        JsonReader reader = Json.createReader(new StringReader(content.toString()));
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
}