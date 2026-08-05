package entity;

import burp.IHttpRequestResponse;
import lombok.Data;
import util.HttpRequestResponse;

@Data
public class ApiData {
    private String method;
    private String url;
    private String path;
    private String summary;
    private HttpRequestResponse httpRequestResponse;
    private String statusCode;
    private String responseSize;

    public ApiData(String method, String url, String path, String summary, HttpRequestResponse httpRequestResponse) {
        this.method = method;
        this.url = url;
        this.path = path;
        this.summary = summary;
        this.httpRequestResponse = httpRequestResponse;
        this.statusCode = null;
        this.responseSize = null;
    }
}
