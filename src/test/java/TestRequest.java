import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.methods.GetMethod;

import java.io.IOException;

public class TestRequest {
    public static void main(String[] args) throws URIException {
        HttpClient httpClient = new HttpClient();
        GetMethod getMethod = new GetMethod("http://www.baidu.com/index.html");
        getMethod.addRequestHeader("accept","*/*");
        getMethod.addRequestHeader("Content-Type","application/x-www-form-urlencoded");
        getMethod.addRequestHeader("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");
        String result = "";
        try {
            int code = httpClient.executeMethod(getMethod);
            if (code == 200){
                result = getMethod.getResponseBodyAsString();
                System.out.println(result);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
