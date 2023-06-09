package entity;

import burp.IHttpRequestResponse;
import lombok.Data;
import util.HttpRequestResponse;

@Data
public class VulData {
    private String url;
    private String size;
    private String issue;
    private HttpRequestResponse iHttpRequestResponse;

    public VulData(String url, String statusCode, String issue, HttpRequestResponse iHttpRequestResponse) {
        this.url = url;
        this.size = statusCode;
        this.issue = issue;
        this.iHttpRequestResponse = iHttpRequestResponse;
    }
}
