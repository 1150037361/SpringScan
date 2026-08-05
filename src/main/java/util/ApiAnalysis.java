package util;

import entity.ApiPathInfo;
import io.swagger.parser.OpenAPIParser;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Swagger/OpenAPI 文档解析工具类。
 * <p>
 * 基于 Swagger Parser（io.swagger.parser.OpenAPIParser）解析 Swagger 2.0 或 OpenAPI 3.x 文档，
 * 将文档中的 paths、parameters、requestBody 等信息转换成统一的 {@link ApiPathInfo} 列表，
 * 供上层（如 BurpExtender）构造请求或展示接口时使用。
 * <p>
 * 解析时启用了 $ref 解析与内联（resolve + resolveFully），因此调用方拿到的 schema 都是完整结构，
 * 无需再手动查询 definitions/components。
 */
public final class ApiAnalysis {

    /**
     * 默认 Content-Type。
     * 当某个接口未在文档中声明请求体媒体类型时，使用该值兜底。
     */
    private static final String DEFAULT_CONTENT_TYPE = "application/json";

    /**
     * 私有构造方法：工具类只提供静态方法，禁止外部实例化。
     */
    private ApiAnalysis() {
        // 工具类，禁止实例化
    }

    /**
     * 解析指定 URL 的 swagger/OpenAPI 文档，提取文档中定义的全部接口信息。
     * <p>
     * 内部流程：调用 {@link OpenAPIParser#readLocation} 读取并解析文档（支持 http/https/file 地址），
     * 从解析结果中取出 OpenAPI 模型，计算基础路径（basePath），再遍历每个路径项及其
     * GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS 方法，逐个生成 {@link ApiPathInfo}。
     * <p>
     * 容错行为：URL 为空、解析失败、文档为空或文档中没有 paths 时，均返回空列表而不抛异常；
     * 解析器的诊断信息（warning/error）会打印到标准错误输出，方便排查问题。
     *
     * @param url swagger/OpenAPI 文档的访问地址。
     *            支持完整 URL（如 http://host/v2/api-docs）和 file 协议（如 file:///D:/swagger.json）；
     *            传入 null 或无法解析的地址不会抛异常，而是返回空列表。
     * @return 文档中所有接口的 {@link ApiPathInfo} 列表。
     * 每个元素包含基础路径、接口路径、请求方法、Content-Type、
     * body/header/query 参数以及接口描述；解析失败时返回空列表（不为 null）。
     */
    public static List<ApiPathInfo> getAllApiPath(URL url) {
        List<ApiPathInfo> apis = new ArrayList<>();
        if (url == null) {
            return apis;
        }

        ParseOptions options = new ParseOptions();
        options.setResolve(true);       // 解析外部 $ref
        options.setResolveFully(true);  // 把 $ref 内联成完整结构，方便直接读取字段

        SwaggerParseResult result;
        try {
            result = new OpenAPIParser().readLocation(url.toString(), null, options);
        } catch (Exception e) {
            System.err.println("[SpringScan] Swagger文档解析异常: " + url);
            e.printStackTrace();
            return apis;
        }

        if (result.getMessages() != null && !result.getMessages().isEmpty()) {
            for (String message : result.getMessages()) {
                System.err.println("[SpringScan] " + message);
            }
        }

        OpenAPI openAPI = result.getOpenAPI();
        if (openAPI == null) {
            System.err.println("[SpringScan] 无法从 " + url + " 解析出 OpenAPI 文档");
            return apis;
        }

        String basePath = resolveBasePath(openAPI);
        Paths paths = openAPI.getPaths();
        if (paths == null) {
            return apis;
        }

        for (Map.Entry<String, PathItem> entry : paths.entrySet()) {
            String path = entry.getKey();
            PathItem item = entry.getValue();
            if (item == null) {
                continue;
            }
            List<Parameter> pathItemParams = item.getParameters();
            collectOperation(apis, "GET", path, basePath, pathItemParams, item.getGet());
            collectOperation(apis, "POST", path, basePath, pathItemParams, item.getPost());
            collectOperation(apis, "PUT", path, basePath, pathItemParams, item.getPut());
            collectOperation(apis, "DELETE", path, basePath, pathItemParams, item.getDelete());
            collectOperation(apis, "PATCH", path, basePath, pathItemParams, item.getPatch());
            collectOperation(apis, "HEAD", path, basePath, pathItemParams, item.getHead());
            collectOperation(apis, "OPTIONS", path, basePath, pathItemParams, item.getOptions());
        }
        return apis;
    }

    /**
     * 收集某个路径项下单个 HTTP 方法的接口信息，并将其加入结果列表。
     * <p>
     * 处理内容：
     * <ul>
     *   <li>合并路径级参数（PathItem 级别）与操作级参数（Operation 级别），路径级参数对
     *       该路径下的所有方法生效，操作级参数仅对当前方法生效；</li>
     *   <li>按参数位置分类：query/header 参数的值统一用样例值填充
     *       （integer/number→1、boolean→true、其他→test），
     *       path 参数用样例值替换路径模板中的占位符；</li>
     *   <li>从 requestBody 中提取 Content-Type 和 body 字段；</li>
     *   <li>接口描述优先取 summary，缺失时回退到 description。</li>
     * </ul>
     * 注意：本方法会直接修改参数 {@code apis} 和局部变量 {@code path}（路径参数填充）。
     *
     * @param apis               结果列表；解析出的 {@link ApiPathInfo} 会被添加到该列表尾部，
     *                           调用方负责传入非空列表
     * @param method             HTTP 方法名（大写），如 "GET"、"POST"、"PUT"、"DELETE" 等，
     *                           会原样写入 ApiPathInfo.method
     * @param path               接口路径模板，如 "/users/{userId}"；若模板中含有路径参数
     *                           占位符，会在处理过程中被替换为样例值（如 "/users/1"）
     * @param basePath           服务的基础路径，如 "/api" 或 "/v2"，与 path 一起写入
     *                           ApiPathInfo，上层拼请求时使用 basePath + path；可为空字符串
     * @param pathItemParameters PathItem 级别的公共参数列表，对该路径下所有 HTTP 方法生效；
     *                           该路径未声明公共参数时可传 null
     * @param operation          当前 HTTP 方法对应的 Operation 对象（描述该方法的具体内容）；
     *                           当该路径未定义此方法（如路径下没有 GET）时为 null，此时方法直接返回
     */
    private static void collectOperation(List<ApiPathInfo> apis, String method, String path, String basePath,
                                         List<Parameter> pathItemParameters, Operation operation) {
        if (operation == null) {
            return;
        }

        // 合并路径级参数与操作级参数，操作级优先级更高
        List<Parameter> parameters = new ArrayList<>();
        if (pathItemParameters != null) {
            parameters.addAll(pathItemParameters);
        }
        if (operation.getParameters() != null) {
            parameters.addAll(operation.getParameters());
        }

        Map<String, String> bodyParams = new HashMap<>();
        Map<String, String> headerParams = new HashMap<>();
        Map<String, String> queryParams = new HashMap<>();

        for (Parameter parameter : parameters) {
            String name = parameter.getName();
            String in = parameter.getIn();
            if (name == null || in == null) {
                continue;
            }
            Schema<?> schema = resolveParameterSchema(parameter);
            switch (in) {
                case "header":
                    headerParams.put(name, sampleValue(schema));
                    break;
                case "query":
                    queryParams.put(name, sampleValue(schema));
                    break;
                case "path":
                    // 路径参数占位符用样例值填充，避免请求里残留 {xxx}
                    path = fillPathParameter(path, name, schema);
                    break;
                default:
                    // cookie 等其他位置暂不处理
                    break;
            }
        }

        String contentType = DEFAULT_CONTENT_TYPE;
        RequestBody requestBody = operation.getRequestBody();
        if (requestBody != null && requestBody.getContent() != null && !requestBody.getContent().isEmpty()) {
            Map.Entry<String, MediaType> first = requestBody.getContent().entrySet().iterator().next();
            contentType = first.getKey();
            Schema<?> bodySchema = first.getValue() == null ? null : first.getValue().getSchema();
            collectBodyFields(bodySchema, bodyParams);
        }

        String summary = operation.getSummary() != null ? operation.getSummary()
                : (operation.getDescription() != null ? operation.getDescription() : "");


        apis.add(new ApiPathInfo(basePath, path, method, contentType,
                bodyParams, headerParams, queryParams, summary));
    }

    /**
     * 获取参数（Parameter）对应的 schema 定义。
     * <p>
     * 在 OpenAPI 规范中，参数可以通过两种方式声明类型：
     * <ul>
     *   <li>直接声明 schema（最常用），如 {@code {in: "query", name: "id", schema: {type: "integer"}}}；</li>
     *   <li>通过 content 媒体类型间接声明 schema，如 header 参数携带 JSON 结构时。</li>
     * </ul>
     * 本方法优先返回 {@code parameter.getSchema()}，若为空再尝试 content 中第一个媒体类型的 schema。
     *
     * @param parameter 待解析的参数对象，描述参数的位置（in）、名称（name）和类型信息
     * @return 参数的 schema 对象；参数既未直接声明 schema 也没有 content 时返回 null
     */
    private static Schema<?> resolveParameterSchema(Parameter parameter) {
        if (parameter.getSchema() != null) {
            return parameter.getSchema();
        }
        Content content = parameter.getContent();
        if (content != null && !content.isEmpty()) {
            MediaType mediaType = content.values().iterator().next();
            return mediaType == null ? null : mediaType.getSchema();
        }
        return null;
    }

    /**
     * 递归提取请求体 schema 中的字段，写入 bodyParams（字段值统一使用样例值）。
     * <p>
     * 处理规则：
     * <ul>
     *   <li>schema 为对象类型（含 properties）时，遍历每个 property，字段名 -> 样例值 写入 bodyParams；</li>
     *   <li>schema 为数组类型时，取其元素（items）的 schema 继续递归，即请求体是对象数组时
     *       提取数组元素的字段；</li>
     *   <li>因为解析阶段已开启 resolveFully，$ref 引用的 schema 已被内联，
     *       因此这里可以直接读取 properties，无需再手动查 definitions/components。</li>
     * </ul>
     *
     * @param schema     请求体（或数组元素）的 schema 定义；为 null 时直接返回，不写入任何字段
     * @param bodyParams 输出参数：请求体字段名 -> 样例值的映射，
     *                   提取结果会被 put 进该 Map，调用方负责传入非空 Map
     */
    private static void collectBodyFields(Schema<?> schema, Map<String, String> bodyParams) {
        if (schema == null) {
            return;
        }
        if (schema.getProperties() != null && !schema.getProperties().isEmpty()) {
            for (Map.Entry<String, Schema> prop : schema.getProperties().entrySet()) {
                bodyParams.put(prop.getKey(), sampleValue(prop.getValue()));
            }
            return;
        }
        // 数组类型的请求体，取其元素字段
        if ("array".equals(schema.getType()) && schema.getItems() != null) {
            collectBodyFields(schema.getItems(), bodyParams);
        }
    }

    /**
     * 将 schema 转换为便于展示和拼接的类型描述字符串。
     * <p>
     * 取值优先级：
     * <ol>
     *   <li>schema 显式声明的 type（如 "string"、"integer"、"object"、"array"、"boolean"）；</li>
     *   <li>未声明 type 但存在 $ref 时，取 $ref 中最后的类型名（如 "Pet"）；</li>
     *   <li>含 properties 的结构视为 "object"；</li>
     *   <li>仅含 enum 枚举值视为 "string"；</li>
     *   <li>以上都不满足时兜底返回 "object"。</li>
     * </ol>
     *
     * @param schema 参数或请求体字段的 schema 定义；为 null 时返回 "object"
     * @return 类型描述字符串，用于填充 ApiPathInfo 中参数 Map 的值
     */
    private static String typeOf(Schema<?> schema) {
        if (schema == null) {
            return "object";
        }
        if (schema.getType() != null) {
            return schema.getType();
        }
        if (schema.get$ref() != null) {
            String ref = schema.get$ref();
            int idx = ref.lastIndexOf('/');
            return idx >= 0 ? ref.substring(idx + 1) : ref;
        }
        if (schema.getProperties() != null && !schema.getProperties().isEmpty()) {
            return "object";
        }
        if (schema.getEnum() != null && !schema.getEnum().isEmpty()) {
            return "string";
        }
        return "object";
    }

    /**
     * 将路径模板中的路径参数占位符替换为样例值。
     * <p>
     * 例如路径 "/users/{userId}" 且参数名为 "userId" 时，会替换成 "/users/1"，
     * 避免上层直接使用模板导致请求 URL 中残留 "{userId}"。
     *
     * @param path   接口路径模板，如 "/users/{userId}"；模板中不含占位符时原样返回
     * @param name   路径参数名（不含花括号），如 "userId"，用于构造占位符 "{userId}"
     * @param schema 路径参数的 schema 定义，用于决定填充的样例值类型
     *               （integer/number 填 "1"，boolean 填 "true"，其他填 "test"）
     * @return 替换占位符后的路径字符串；模板中不存在该参数占位符时返回原路径
     */
    private static String fillPathParameter(String path, String name, Schema<?> schema) {
        String placeholder = "{" + name + "}";
        if (!path.contains(placeholder)) {
            return path;
        }
        return path.replace(placeholder, sampleValue(schema));
    }

    /**
     * 根据 schema 的类型生成一个样例值字符串，用于填充路径参数。
     *
     * @param schema 路径参数的 schema 定义；为 null 或类型不明时按默认规则返回 "test"
     * @return 样例值：integer/number → "1"，boolean → "true"，其他类型 → "test"
     */
    private static String sampleValue(Schema<?> schema) {
        switch (typeOf(schema)) {
            case "integer":
            case "number":
                return "1";
            case "boolean":
                return "true";
            default:
                return "test";
        }
    }

    /**
     * 从 OpenAPI 模型的 servers 列表中提取基础路径（basePath）。
     * <p>
     * OpenAPI 3.x 用 servers 声明服务地址，如 "http://demo.com/api"；
     * Swagger 2.0 的 basePath 经 OpenAPIParser 转换后也会落到 server URL 中。
     * 这里只截取 URL 中主机名之后的路径部分（如 "/api"），并去掉尾部斜杠，
     * 保证后续 "basePath + path" 拼接出的路径不会出现 "//" 或尾部冗余斜杠。
     *
     * @param openAPI 解析成功后的 OpenAPI 模型对象（非 null）
     * @return 基础路径字符串；无 servers、server URL 为空或不含路径时返回空字符串
     */
    private static String resolveBasePath(OpenAPI openAPI) {
        if (openAPI.getServers() == null || openAPI.getServers().isEmpty()
                || openAPI.getServers().get(0).getUrl() == null) {
            return "";
        }
        String serverUrl = openAPI.getServers().get(0).getUrl().trim();
        String path = "";
        if (serverUrl.startsWith("http://") || serverUrl.startsWith("https://")) {
            try {
                path = new URL(serverUrl).getPath();
            } catch (MalformedURLException e) {
                path = "";
                return path;
            }
        } else if (serverUrl.startsWith("//")) {
            int schemeEnd = serverUrl.indexOf("//");
            int idx = serverUrl.indexOf('/', schemeEnd + 2);
            path = serverUrl.substring(idx);
            if (path.endsWith("/")) {
                path = "";
            }
        } else if (serverUrl.startsWith("/")) {
            path = serverUrl;
        } else {
            path = "";

        }
        return path;
    }
}
