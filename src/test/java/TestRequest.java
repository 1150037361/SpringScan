import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class TestRequest {
    public static void main(String[] args) throws IOException {
        String url = "https://www.example.com/";
        List<String> results = getUrlChildren(url, 2);

        for (int i = 0; i< results.size();i++) {
            results.set(i, results.get(i) + " HTTP/1.1");
        }

        results.forEach(s -> System.out.println(s));
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
                return  subdirectories;
            }
        } catch (MalformedURLException e) {
            System.out.println("Invalid URL");
            return null;
        }
    }
}
