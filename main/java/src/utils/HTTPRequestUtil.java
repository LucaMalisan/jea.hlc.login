package src.utils;

import lombok.extern.java.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

@Log
public class HTTPRequestUtil {

    private HTTPRequestUtil() {
    }

    public static String httpRequest(String urlStr, String method) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod(method);
        con.setRequestProperty("Content-Type", "application/json");
        con.setConnectTimeout(5000);
        con.setReadTimeout(5000);

        if (con.getResponseCode() < 300) {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));) {
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                con.disconnect();
                return content.toString();
            }
        }
        con.disconnect();
        return null;
    }
}
