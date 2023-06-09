import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import entity.ApiPathInfo;
import util.HttpUtil;

import java.util.*;

public class Test {

    public static void main(String[] args)  {
        List<ApiPathInfo> apiInfo = new ArrayList<>();
        Map<String,String> paramBody = new HashMap<>();
        Map<String,String> paramHeader = new HashMap<>();
        Map<String,String> paramQuery = new HashMap<>();
        List<ApiPathInfo> apis = new ArrayList<>();
        String url = "https://www.onstar.com.cn/mssos/sos/mobileaggr/v2/api-docs";
        String result = HttpUtil.doGet(url);
        JSONObject api = JSON.parseObject(result);
        String basePath = (String) api.get("basePath");
        JSONObject definitionsJson = api.getJSONObject("definitions");   //definitions的JSON数据
        JSONObject definitionsData = new JSONObject();

        for (String key : definitionsJson.keySet()) {
            definitionsData.put(key.toLowerCase(), definitionsJson.get(key));
        }


        JSONObject apiPath = (JSONObject) api.get("paths");  //paths的json数据

        //获取key
        for (Map.Entry<String,Object> pathEntry: apiPath.entrySet()) {
            String path = pathEntry.getKey();
            JSONObject pathJson = (JSONObject) pathEntry.getValue();
            //获取请求方法
            for (Map.Entry<String,Object> methodEntry: pathJson.entrySet()){
                String method = methodEntry.getKey();   //请求方法
                JSONObject methodJson = (JSONObject) methodEntry.getValue();    //请求方法内部json数据
                String reuqestSummary = (String) methodJson.get("summary");     //接口描述
                String contentType = methodJson.getJSONArray("produces").getString(0);  //contentType类型

                JSONArray parameters = methodJson.getJSONArray("parameters");   //字段属性

                //判断字段是否为空
                if (parameters == null) {
                    continue;
                }

                //循环获取字段内的属性
                for (int i = 0; i < parameters.size(); i++) {
                    JSONObject dataJson = JSONObject.parseObject(parameters.getString(i));

                    String parameterPosition = (String) dataJson.get("in");  //字段的位置

                    if (parameterPosition.equals("header")) {
                        paramHeader.put(dataJson.getString("name"),dataJson.getString("type"));
                    } else if (parameterPosition.equals("body")) {
                        if (dataJson.containsKey("schema")) {
                            JSONObject data2 = definitionsData.getJSONObject(dataJson.getString("name").toLowerCase());
                            if (data2 !=null) {
                                JSONObject data3 = data2.getJSONObject("properties");
                                for (Map.Entry<String, Object> param: data3.entrySet()) {
                                    JSONObject test = (JSONObject) param.getValue();
                                    paramBody.put(param.getKey(),test.getString("type"));
                                }
                            }
                        } else {
                            paramBody.put(dataJson.getString("name"),dataJson.getString("type"));
                        }
                    } else if (parameterPosition.equals("query")) {
                        paramQuery.put(dataJson.getString("name"),dataJson.getString("type"));
                    }
                }
                apis.add(new ApiPathInfo(basePath,path,method,contentType,paramBody,paramHeader,paramQuery,reuqestSummary));
            }

        }

        for (ApiPathInfo data: apis) {
            System.out.println(data.path);
        }



    }


    public static List<String> getAllKeys(JSONObject path) {
        Set<String> pt= path.keySet();
        return new ArrayList<>(pt);
    }

    public static void buildRequest(List<String> paths) {

    }

    public static Map<String,String> getParameters(String objectName,JSONObject definitionsJson) {
        Map<String ,String> result = null;
        JSONObject objectData = definitionsJson.getJSONObject(objectName);
        JSONObject propertiesJson = objectData.getJSONObject("properties");

        for (Map.Entry<String ,Object> param: propertiesJson.entrySet()) {
            JSONObject typeValue = (JSONObject) param.getValue();
            result.put(param.getKey(), (String) typeValue.get("type"));
        }
        return result;
    }


}
