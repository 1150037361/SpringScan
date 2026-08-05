import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import entity.ApiPathInfo;
import util.ApiAnalysis;
import util.HttpUtil;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class Test {

    public static void main(String[] args) throws Exception {
        String url1 = "https://ors.chinapost-life.com/ors/auth/graph";
        String url2 = "https://ors.chinapost-life.com/";
        URL url = new URL(url2);
        System.out.println(url.getPath());
    }

    /**
     * 命令行参数转 URL：带协议的直接使用，否则按本地文件处理。
     */
    private static URL toUrl(String input) throws Exception {
        if (input.contains("://")) {
            return new URL(input);
        }
        return new URL("file:///" + input.replace("\\", "/"));
    }

    /**
     * 内置一份 Swagger 2.0 样例，写入临时文件后返回 file URL，方便无网络时测试。
     */
    private static URL sampleSwaggerUrl() throws IOException {
        String[] lines = {
                "{",
                "  \"swagger\": \"2.0\",",
                "  \"info\": {\"title\": \"Petstore\", \"version\": \"1.0.0\"},",
                "  \"host\": \"petstore.swagger.io\",",
                "  \"schemes\": [\"https\"],",
                "  \"basePath\": \"/v2\",",
                "  \"paths\": {",
                "    \"/pet\": {",
                "      \"post\": {",
                "        \"summary\": \"Add a new pet\",",
                "        \"consumes\": [\"application/json\"],",
                "        \"parameters\": [",
                "          {\"in\": \"body\", \"name\": \"body\", \"required\": true, \"schema\": {\"$ref\": \"#/definitions/Pet\"}},",
                "          {\"in\": \"header\", \"name\": \"X-API-Key\", \"type\": \"string\"}",
                "        ],",
                "        \"responses\": {\"200\": {\"description\": \"ok\"}}",
                "      }",
                "    },",
                "    \"/pet/findByStatus\": {",
                "      \"get\": {",
                "        \"summary\": \"Finds pets by status\",",
                "        \"parameters\": [",
                "          {\"in\": \"query\", \"name\": \"status\", \"type\": \"array\", \"items\": {\"type\": \"string\"}}",
                "        ],",
                "        \"responses\": {\"200\": {\"description\": \"ok\"}}",
                "      }",
                "    },",
                "    \"/pet/{petId}\": {",
                "      \"get\": {",
                "        \"summary\": \"Find pet by ID\",",
                "        \"parameters\": [",
                "          {\"in\": \"path\", \"name\": \"petId\", \"required\": true, \"type\": \"integer\"}",
                "        ],",
                "        \"responses\": {\"200\": {\"description\": \"ok\"}}",
                "      }",
                "    }",
                "  },",
                "  \"definitions\": {",
                "    \"Pet\": {",
                "      \"type\": \"object\",",
                "      \"properties\": {",
                "        \"id\": {\"type\": \"integer\"},",
                "        \"name\": {\"type\": \"string\"},",
                "        \"status\": {\"type\": \"string\"}",
                "      }",
                "    }",
                "  }",
                "}"
        };
        Path tmp = Files.createTempFile("swagger-sample", ".json");
        Files.write(tmp, String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
        tmp.toFile().deleteOnExit();
        return new URL("file:///" + tmp.toString().replace("\\", "/"));
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
