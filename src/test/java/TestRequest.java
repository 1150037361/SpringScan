import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class TestRequest {
    public static void main(String[] args) throws IOException {
        String data = "https://www.onstar.com.cn/mssos/sos/mobileaggr/v2/api-docs";
        URL url = new URL(data);
        System.out.println(url.getPath());
    }

    public static List<String> getUrlChildren(String urlStr, Integer n) {
        try {
            List<String> subdirectories = new ArrayList<>();
            URL url = new URL(urlStr);
            String path = url.getPath();
            String[] parts = path.split("/");
            if (parts.length < n) {
                subdirectories.add("GET ");
                return subdirectories;
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append("GET ");
                for (int i = 1; i <= n && i < parts.length; i++) {
                    sb.append("/");
                    sb.append(parts[i]);
                    subdirectories.add(sb.toString());
                }
                subdirectories.add("GET ");
                return  subdirectories;
            }
        } catch (MalformedURLException e) {
            System.out.println("Invalid URL");
            return null;
        }
    }
}
