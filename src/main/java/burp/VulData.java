package burp;

import lombok.Data;

@Data
public class VulData {
    private String url;
    private String size;
    private String issue;
    private IHttpRequestResponse iHttpRequestResponse;

    public VulData(String url, String statusCode, String issue, IHttpRequestResponse iHttpRequestResponse) {
        this.url = url;
        this.size = statusCode;
        this.issue = issue;
        this.iHttpRequestResponse = iHttpRequestResponse;
    }
}
