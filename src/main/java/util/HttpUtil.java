package util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Map;

/**
 * 基于 HttpURLConnection 的轻量 HTTP 工具类。
 * 2xx 返回响应体，非 2xx 时若有错误内容则返回错误内容，否则返回空字符串。
 */
public final class HttpUtil {

    private static final int DEFAULT_TIMEOUT = 60000;
    private static final String DEFAULT_CHARSET = "UTF-8";
    private static final String DEFAULT_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36";

    private HttpUtil() {
        // 工具类，禁止实例化
    }

    public static String doGet(String url) throws IOException {
        return doGet(url, null, DEFAULT_TIMEOUT, DEFAULT_CHARSET);
    }

    public static String doGet(String url, Map<String, String> headers) throws IOException {
        return doGet(url, headers, DEFAULT_TIMEOUT, DEFAULT_CHARSET);
    }

    public static String doGet(String url, Map<String, String> headers, int timeoutMillis, String charset)
            throws IOException {
        return request("GET", url, headers, null, timeoutMillis, charset);
    }

    public static String doPost(String url, Map<String, String> headers, String body) throws IOException {
        return doPost(url, headers, body, DEFAULT_TIMEOUT, DEFAULT_CHARSET);
    }

    public static String doPost(String url, Map<String, String> headers, String body, int timeoutMillis, String charset)
            throws IOException {
        return request("POST", url, headers, body, timeoutMillis, charset);
    }

    private static String request(String method, String url, Map<String, String> headers, String body,
                                  int timeoutMillis, String charset) throws IOException {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL不能为空");
        }
        if (charset == null || charset.trim().isEmpty()) {
            charset = DEFAULT_CHARSET;
        }
        Charset cs = Charset.forName(charset);

        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        try {
            conn.setRequestMethod(method);
            conn.setConnectTimeout(timeoutMillis);
            conn.setReadTimeout(timeoutMillis);
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("User-Agent", DEFAULT_USER_AGENT);

            if (body != null) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=" + cs.name());
            }

            // 自定义请求头覆盖默认值
            if (headers != null) {
                headers.forEach(conn::setRequestProperty);
            }

            if (body != null) {
                byte[] data = body.getBytes(cs);
                conn.setFixedLengthStreamingMode(data.length);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(data);
                }
            }

            int statusCode = conn.getResponseCode();
            InputStream in = (statusCode >= 200 && statusCode < 300)
                    ? conn.getInputStream()
                    : conn.getErrorStream();
            return in == null ? "" : readAll(in, cs);
        } finally {
            conn.disconnect();
        }
    }

    private static String readAll(InputStream in, Charset charset) throws IOException {
        StringBuilder sb = new StringBuilder();
        char[] buffer = new char[8192];
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, charset))) {
            int len;
            while ((len = reader.read(buffer)) != -1) {
                sb.append(buffer, 0, len);
            }
        }
        return sb.toString();
    }
}
