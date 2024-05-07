package src.utils;

import ch.qos.logback.core.util.StringCollectionUtil;
import io.micrometer.common.util.StringUtils;
import lombok.extern.java.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

@Log
public class HTTPRequestUtil {

    private HTTPRequestUtil() {
    }

    public static String httpRequest(String urlStr, String method, String authorization, String data) throws IOException {

        String base64AuthorizationHeader = "Basic " + Base64.getEncoder().encodeToString(authorization.getBytes());

        URL url = new URL(urlStr);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        //header
        con.setRequestMethod(method);
        con.setRequestProperty("Authorization", base64AuthorizationHeader);

        //payload
        if (!StringUtils.isEmpty(data)) {
            con.setDoOutput(true);
            OutputStream os = con.getOutputStream();
            os.write(data.getBytes());
            os.flush();
            os.close();
        }

        //open connection
        con.setConnectTimeout(5000);
        con.setReadTimeout(5000);

        //    if (con.getResponseCode() < 300) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));) {
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            con.disconnect();

            if (con.getResponseCode() >= 300) {
                log.severe("Getting JWT token failed with message: " + con.getResponseMessage());
            }

            return content.toString();
        }
    }
}
