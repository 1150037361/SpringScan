package util;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import lombok.Data;

import java.util.Arrays;
import java.util.List;

/**
 * 重写IHttpRequestResponse接口，不然无法修改request信息，没有权限
 */
@Data
public class HttpRequestResponse implements IHttpRequestResponse {
    public byte[] request;
    public byte[] response;
    public IHttpService iHttpService;
    public IHttpRequestResponse iHttpRequestResponse;
    public String comment;
    public String highlight;
    public BurpExtender burpExtender;

    public HttpRequestResponse(IHttpRequestResponse iHttpRequestResponse, BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.request = iHttpRequestResponse.getRequest();
        this.response = iHttpRequestResponse.getResponse();
        this.iHttpService = iHttpRequestResponse.getHttpService();
        this.comment = iHttpRequestResponse.getComment();
        this.highlight = iHttpRequestResponse.getHighlight();
    }

    public String getPath() {
        String h0 = burpExtender.helpers.analyzeRequest(request).getHeaders().get(0);
        String path = h0.split(" ")[1];
        return path;
    }

    /**
     * 修改当前请求的 path，设置为自定义路径，并同步更新 request 字节数组。
     * <p>
     * 通过解析请求首行（如 "GET /api/users/1?x=1 HTTP/1.1"），只替换其中的路径部分，
     * 保留请求方法、协议版本和 body，最后用 Burp helpers 重建请求。
     * 若新 path 未携带 query 参数，会保留原路径上的 query（如上例传 "/v2/pet"，
     * 结果为 "GET /v2/pet?x=1 HTTP/1.1"）；若新 path 自带 "?"，则完全按传入值替换。
     *
     * @param path 自定义的请求路径，如 "/v2/pet"；为 null 或空字符串时不修改请求
     */
    public void setPath(String path) {
        if (path == null || path.trim().isEmpty() || request == null) {
            return;
        }
        List<String> headers = burpExtender.helpers.analyzeRequest(request).getHeaders();
        if (headers == null || headers.isEmpty()) {
            return;
        }
        String[] parts = headers.get(0).trim().split("\\s+");
        if (parts.length < 2) {
            return;
        }

        String method = parts[0];
        String version = parts.length >= 3 ? parts[2] : "HTTP/1.1";
        String newPath = path.trim();

        // 新 path 未携带 query 时，保留原请求路径上的 query 参数
        if (!newPath.contains("?")) {
            int queryIndex = parts[1].indexOf('?');
            if (queryIndex >= 0) {
                newPath = newPath + parts[1].substring(queryIndex);
            }
        }

        headers.set(0, method + " " + newPath + " " + version);
        // 通过 body 起始偏移量截取原始请求中的 body
        int bodyOffset = burpExtender.helpers.analyzeRequest(request).getBodyOffset();
        byte[] body = bodyOffset >= request.length ? new byte[0] : Arrays.copyOfRange(request, bodyOffset, request.length);
        this.request = burpExtender.helpers.buildHttpMessage(headers, body);
    }

    @Override
    public String getComment() {
        return iHttpRequestResponse.getComment();
    }

    @Override
    public void setComment(String comment) {
        iHttpRequestResponse.setComment(comment);
    }

    @Override
    public String getHighlight() {
        return iHttpRequestResponse.getHighlight();
    }

    @Override
    public void setHighlight(String color) {
        iHttpRequestResponse.setHighlight(color);
    }

    @Override
    public IHttpService getHttpService() {
        return iHttpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        iHttpRequestResponse.setHttpService(httpService);
    }

    public static void main(String[] args) {

    }
}
