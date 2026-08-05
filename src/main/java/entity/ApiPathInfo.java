package entity;

import java.util.Map;

public class ApiPathInfo {
    public String basePath;   //基础请求路径
    public String path;   //请求路径
    public String method;   //请求方法
    public String contentType;  //数据类型
    public Map<String,String> parametesBody;  //请求Body字段
    public Map<String,String> parametesHeader;  //请求Header字段
    public Map<String,String> parametesQueue;  //请求Query字段
    public String summary;   //接口描述

    public ApiPathInfo(String basePath, String path, String method, String contentType, Map<String, String> parametesBody, Map<String, String> parametesHeader, Map<String, String> parametesQueue, String summary) {
        this.basePath = basePath;
        this.path = path;
        this.method = method;
        this.contentType = contentType;
        this.parametesBody = parametesBody;
        this.parametesHeader = parametesHeader;
        this.parametesQueue = parametesQueue;
        this.summary = summary;
    }
}
