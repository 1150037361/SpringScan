package util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

public class HttpUtil {

    public static String doGet(String url) {
        StringBuilder result = new StringBuilder();
        HttpURLConnection conn = null;
        BufferedReader br = null;
        String content;

        try {
            URL u = new URL(url);
            conn = (HttpURLConnection) u.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(60000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("Connection", "close");
            conn.setRequestProperty("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");
            conn.setRequestProperty("Content-Type","application/x-www-form-urlencoded");

            if (conn.getResponseCode() == 200){
                br = new BufferedReader(new InputStreamReader(conn.getInputStream(),"utf-8"));
                while ((content = br.readLine()) != null){
                    result.append(content);
                }
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null){
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null){
                conn.disconnect();
            }
        }
        return result.toString();
    }
}
