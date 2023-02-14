package burp;

import lombok.Data;
import tableMode.PathTableMode;
import tableMode.ValueTableMode;
import tableMode.VulTableMode;
import ui.MainTab;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

@Data
public class BurpExtender implements IBurpExtender, ITab, IMessageEditorController, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;  //输出数据
    private JPanel rootPanel;
    private VulTableMode vulTableMode;
    private PathTableMode pathTableMode;
    private ValueTableMode valueTableMode;
    private Table vulInfoTable;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    private VulData data;
    private MainTab ui;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SpringScan_test");
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("-------------------------------");
        stdout.println("[+] Author: against");
        stdout.println("[+] ExtenderName: SpringScan");
        stdout.println("-------------------------------");
        callbacks.registerHttpListener(this);

        //新建一个线程来运行UI界面
        buildUi();
    }

    public void buildUi() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                vulTableMode = new VulTableMode();
                pathTableMode = new PathTableMode();
                valueTableMode = new ValueTableMode();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this,false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this,false);

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
        if (i == 4) {
            if (!b) {
                //stdout.println(helpers.analyzeRequest(iHttpRequestResponse).getUrl());
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        checkVul(iHttpRequestResponse);
                    }
                });
                thread.start();
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
            stdout.println(header.get(0));
            byte[] newMessage = helpers.buildHttpMessage(header, null);
            String url = String.valueOf(helpers.analyzeRequest(iHttpRequestResponse.getHttpService(), newMessage).getUrl());

            if (vulTableMode.contiansUrl(url)) {
                continue;
            }

            IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), newMessage);
            //判断返回值是否是200
            if (helpers.analyzeResponse(resp.getResponse()).getStatusCode() == 200) {
                //判断返回的内容是否符合POC
                if (isGood(helpers.bytesToString(resp.getResponse()).toLowerCase())) {
                    if (!vulTableMode.contiansUrl(url)) {
                        vulTableMode.addRow(new VulData(url, String.valueOf(helpers.bytesToString(resp.getResponse()).length()), "true", resp));
                    }
                }
            }
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
            List<String > childrenPaths = getUrlChildren(url, Integer.valueOf(index));
            List<String > result = new ArrayList<>();

            for (int i = 0; i<childrenPaths.size(); i++) {
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

    /**
     * 判断此次请求是否符合结果
     *
     * @param result
     * @return
     */
    public Boolean isGood(String result) {
        String data = result;

        for (String comp : valueTableMode.getValueData()) {
            if (data.contains(comp)) {
                return true;
            }
        }
        return false;

//        if (data.contains("swagger-ui.css") || data.contains("******") || data.contains("swaggerversion") ||
//                data.contains("actuator/info") || data.contains("actuator/health") || data.contains("profiles") ||
//                data.contains("\"swagger\"")) {
//            return true;
//        } else {
//            return false;
//        }

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
                return  subdirectories;
            }
        } catch (MalformedURLException e) {
            System.out.println("Invalid URL");
            return null;
        }
    }
}
