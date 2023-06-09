package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import entity.ApiData;
import entity.VulData;
import exTable.Table;
import lombok.Data;
import tableMode.ApiTableMode;
import tableMode.PathTableMode;
import tableMode.ValueTableMode;
import tableMode.VulTableMode;
import ui.MainTab;
import util.ApiAnalysis;
import entity.ApiPathInfo;
import util.HttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import static java.lang.Thread.sleep;

@Data
public class BurpExtender implements IBurpExtender, ITab, IMessageEditorController, IHttpListener, IContextMenuFactory {
    private String jsonFile = "SpringScan_Setting.json";
    private JSONObject config = new JSONObject();
    private IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private PrintWriter stdout;  //输出数据
    private JPanel rootPanel;

    private VulTableMode vulTableMode;
    private PathTableMode pathTableMode;
    private ValueTableMode valueTableMode;
    private ApiTableMode apiTableMode;

    private Table vulInfoTable;
    private Table apiInfoTable;

    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    private IMessageEditor apiRequestViewer;
    private IMessageEditor apiResponseViewer;

    private HttpRequestResponse currentlyDisplayedItem;

    private VulData data;
    private ApiData apiData;

    private MainTab ui;

    private ExecutorService executor;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SpringScan");
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("-------------------------------");
        stdout.println("[+] Author: against");
        stdout.println("[+] ExtenderName: SpringScan");
        stdout.println("[+] ProjectAddress: https://github.com/1150037361/SpringScan");
        stdout.println("-------------------------------");

        //创建大小为1的线程池，便于慢速模式使用
        executor = Executors.newFixedThreadPool(1);

        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);
        //新建一个线程来运行UI界面
        buildUi();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> menu_item_list = new ArrayList<JMenuItem>();
        JMenuItem sendScanItem = new JMenuItem("Spring接口扫描");
        JMenuItem apiScanItem = new JMenuItem("API接口分析");

        sendScanItem.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        checkVul(iContextMenuInvocation.getSelectedMessages()[0]);
                    }
                });
                thread.start();
            }
        });

        apiScanItem.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new Thread(() -> {
                    apiAnalysis(iContextMenuInvocation.getSelectedMessages()[0]);
                }).start();
            }
        });


        menu_item_list.add(sendScanItem);
        menu_item_list.add(apiScanItem);
        return menu_item_list;
    }

    public void buildUi() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                vulTableMode = new VulTableMode();
                pathTableMode = new PathTableMode(BurpExtender.this);
                valueTableMode = new ValueTableMode(BurpExtender.this);
                apiTableMode = new ApiTableMode();

                loadConfigFromJson();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);

                apiRequestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                apiResponseViewer = callbacks.createMessageEditor(BurpExtender.this, false);

                rootPanel = new JPanel();
                ui = new MainTab(BurpExtender.this);
                rootPanel.add(ui.$$$getRootComponent$$$());
                rootPanel.setLayout(new GridLayout(1, 1));
                callbacks.customizeUiComponent(rootPanel);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    //Itab内的一个方法的实现，返回burpsuite上的标签名称
    @Override
    public String getTabCaption() {
        return "SpringScan";
    }

    //Itab内实现的方法，返回一个界面展示
    @Override
    public Component getUiComponent() {
        return rootPanel;
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }


    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    /**
     * IHttpListener接口必须实现的方法
     *
     * @param i                    此参数为从哪个模块过来的流量; 此处是用的4，即proxy过来的流量
     * @param b                    此参数为该次数据流到底是请求服务的流量还是服务响应的流量
     * @param iHttpRequestResponse 此次数据的请求数据和响应数据
     */
    @Override
    public void processHttpMessage(int i, boolean b, IHttpRequestResponse iHttpRequestResponse) {
        //是否启动被动扫描
        if (ui.scanEnableCheckBox.isSelected()) {
            //是否为proxy模块的流量
            if (i == 4) {
                //是否为请求数据包
                if (!b) {
                    //stdout.println(helpers.analyzeRequest(iHttpRequestResponse).getUrl());
                    Thread thread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            checkVul(iHttpRequestResponse);
                        }
                    });

                    //慢速模式将线程添加到线程池
                    if (ui.scanSlowCheckBox.isSelected()) {
                        try {
                            sleep(200);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                        executor.execute(thread);
                    //正常模式直接执行线程
                    } else {
                        thread.start();
                    }
                }
            }
        }
    }

    /**
     * 检测请求的是否满足pauload
     *
     * @param iHttpRequestResponse
     */
    public void checkVul(IHttpRequestResponse iHttpRequestResponse) {
        List<String> header = helpers.analyzeRequest(iHttpRequestResponse).getHeaders();
        List<String> result = bulidUrl(iHttpRequestResponse);
        if (result == null) {
            return;
        }
        for (String info : result) {
            header.set(0, info);
            byte[] newMessage = helpers.buildHttpMessage(header, null);
            String url = String.valueOf(helpers.analyzeRequest(iHttpRequestResponse.getHttpService(), newMessage).getUrl());
            if (vulTableMode.contiansUrl(url)) {
                continue;
            }

            if (ui.scanSlowCheckBox.isSelected()) {
                try {
                    sleep(100);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), newMessage);
            //判断返回值是否是200
            if (helpers.analyzeResponse(resp.getResponse()).getStatusCode() == 200) {
                //判断返回的内容是否符合POC
                if (isGood(helpers.bytesToString(resp.getResponse()).toLowerCase())) {
                    if (!vulTableMode.contiansUrl(url)) {
                        vulTableMode.addRow(new VulData(url, String.valueOf(helpers.bytesToString(resp.getResponse()).length()), "true", new HttpRequestResponse(resp, BurpExtender.this)));
                    }
                }
            }
        }
    }

    //分析api-docs接口地址方法
    public void apiAnalysis(IHttpRequestResponse iHttpRequestResponse) {
        URL url = helpers.analyzeRequest(iHttpRequestResponse).getUrl();
        List<ApiPathInfo> allApiPath = ApiAnalysis.getAllApiPath(url);

        apiRequestViewer.setMessage("".getBytes(), false);
        apiResponseViewer.setMessage("".getBytes(), false);
        apiTableMode.clearRow();

        for (ApiPathInfo pathInfo : allApiPath) {
            HttpRequestResponse data = buildRequest(pathInfo, iHttpRequestResponse);
            apiTableMode.addRow(new ApiData(pathInfo.method.toUpperCase(), data.getPath(), pathInfo.summary, data));
        }
    }

    /**
     * 返回请求头的第一行即【GET /xxx/xxx HTTP/1.1】这种
     * 函数主要就是接收原来的请求头，然后切割第一行的数据，加工拼接上相关的payload
     *
     * @param iHttpRequestResponse
     * @return
     */
    public List<String> bulidUrl(IHttpRequestResponse iHttpRequestResponse) {
        try {
            String url = String.valueOf(helpers.analyzeRequest(iHttpRequestResponse).getUrl());
            if (url.contains(".js") || url.contains(".png") || url.contains(".jpg") || url.contains(".css") || url.contains(".woff") || url.contains(".ico")) {
                return null;
            }
            String index = (String) ui.scanIndexBox.getSelectedItem();
            List<String> childrenPaths = getUrlChildren(url, Integer.valueOf(index));
            List<String> result = new ArrayList<>();

            for (int i = 0; i < childrenPaths.size(); i++) {
                for (String payload : pathTableMode.getPathData()) {
                    result.add(i, childrenPaths.get(i) + payload + " HTTP/1.1");
                }
            }
            return result;
        } catch (Exception e) {
            stdout.println(e);
            return null;
        }
    }

    //构造Api的HttpRequestResponse数据
    public HttpRequestResponse buildRequest(ApiPathInfo apiPathInfo, IHttpRequestResponse iHttpRequestResponse) {
        HttpRequestResponse requestResponse = new HttpRequestResponse(iHttpRequestResponse, BurpExtender.this);
        byte[] newRquest = requestResponse.getRequest();
        newRquest = buildApiHeader(newRquest, apiPathInfo);

        //URL内的参数,这里不知道为什么helps的addParameter方法失效了，自己写了给方法
        stdout.println("add parameter");
        if (apiPathInfo.parametesQueue.size() != 0) {
            for (Map.Entry<String, String> param : apiPathInfo.parametesQueue.entrySet()) {
                newRquest = addParam(newRquest, param.getKey(), param.getValue());
            }
        }
        //header内的参数
        stdout.println("add header");
        if (apiPathInfo.parametesHeader.size() != 0) {
            List<String> headers = helpers.analyzeRequest(newRquest).getHeaders();
            for (Map.Entry<String, String> header : apiPathInfo.parametesHeader.entrySet()) {
                headers.add(header.getKey() + ": " + header.getValue());
            }
            newRquest = helpers.buildHttpMessage(headers, null);
        }
        //body内的参数
        stdout.println("add body");
        if (apiPathInfo.parametesBody != null) {
            newRquest = helpers.buildHttpMessage(helpers.analyzeRequest(newRquest).getHeaders(), JSON.toJSONBytes(apiPathInfo.parametesBody));
        }

        requestResponse.setRequest(newRquest);
        requestResponse.setResponse("".getBytes());
        return requestResponse;
    }

    public byte[] addParam(byte[] request, String key, String value) {
        List<String> headers = helpers.analyzeRequest(request).getHeaders();
        String path;
        String pathData = headers.get(0);
        String[] pathInfo = pathData.split(" ");
        if (!pathInfo[1].contains("?")) {
            path = pathInfo[1] + "?" + key + "=" + value;
        } else {
            path = pathInfo[1] + "&" + key + "=" + value;
        }
        headers.set(0, pathInfo[0] + " " + path + " " + pathInfo[2]);
        return helpers.buildHttpMessage(headers, null);
    }

    public byte[] buildApiHeader(byte[] req, ApiPathInfo apiPathInfo) {
        List<String> headers = helpers.analyzeRequest(req).getHeaders();
        headers.set(0, apiPathInfo.method.toUpperCase() + " " + apiPathInfo.basePath + apiPathInfo.path + " HTTP/1.1");
        for (String header : headers) {
            if (header.startsWith("Content-Type")) {
                headers.remove(header);
            }
        }
        headers.add("Content-Type: application/json");

        return helpers.buildHttpMessage(headers, null);
    }

    /**
     * 判断此次请求是否符合结果
     *
     * @param result
     * @return
     */
    public Boolean isGood(String result) {
        for (String comp : valueTableMode.getValueData()) {
            if (result.contains(comp)) {
                return true;
            }
        }
        return false;
    }

    public void saveConfigToJson() {
        String configJson = this.config.toString();
        callbacks.saveExtensionSetting(jsonFile, configJson);
    }

    public void loadConfigFromJson() {
        String content = callbacks.loadExtensionSetting(jsonFile);
        if (content != null) {
            config = JSON.parseObject(content);
            pathTableMode.setPathData(JSON.parseArray(config.getString("path"), String.class));
            valueTableMode.setValueData(JSON.parseArray(config.getString("value"), String.class));
        } else {
            config.put("path", Path.fullPath);
            config.put("value", Path.values);
            saveConfigToJson();
            content = callbacks.loadExtensionSetting(jsonFile);
            config = JSON.parseObject(content);
            pathTableMode.setPathData(JSON.parseArray(config.getString("path"), String.class));
            valueTableMode.setValueData(JSON.parseArray(config.getString("value"), String.class));
        }
    }


    public List<String> getUrlChildren(String urlStr, Integer n) {
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
                subdirectories.add("GET ");
                return subdirectories;
            }
        } catch (MalformedURLException e) {
            System.out.println("Invalid URL");
            return null;
        }
    }
}
