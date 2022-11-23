package burp;

import lombok.Data;
import ui.MainTab;
import util.HttpUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

@Data
public class BurpExtender implements IBurpExtender, ITab, IMessageEditorController, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;  //输出数据
    private JPanel rootPanel;    //UI的被动扫描界面
    private TableMode tableMode;
    private Table vulInfoTable;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    private VulData data;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SpringScan");
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
                tableMode = new TableMode();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this,false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this,false);

                rootPanel = new JPanel();
                MainTab ui = new MainTab(BurpExtender.this);
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
        List<String> result = bulidUrl(header);
        if (result == null) {
            return;
        }
        for (String info : result) {
            header.set(0, info);
            byte[] newMessage = helpers.buildHttpMessage(header, null);
            String url = String.valueOf(helpers.analyzeRequest(iHttpRequestResponse.getHttpService(), newMessage).getUrl());

            if (tableMode.contiansUrl(url)) {
                continue;
            }

            IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), newMessage);
            //判断返回值是否是200
            if (helpers.analyzeResponse(resp.getResponse()).getStatusCode() == 200) {
                //判断返回的内容是否符合POC
                if (isGood(helpers.bytesToString(resp.getResponse()).toLowerCase())) {
                    if (!tableMode.contiansUrl(url)) {
                        tableMode.addRow(new VulData(url, String.valueOf(helpers.bytesToString(resp.getResponse()).length()), "true", resp));
                    }
                }
            }
        }
    }

    /**
     * 返回请求头的第一行即【GET /xxx/xxx HTTP/1.1】这种
     * 函数主要就是接收原来的请求头，然后切割第一行的数据，加工拼接上相关的payload
     *
     * @param headers
     * @return
     */
    public List<String> bulidUrl(List<String> headers) {
        String path = headers.get(0);
        String[] header = path.split(" ");
        if (header[1].contains(".js") || header[1].contains(".png") || header[1].contains(".jpg") || header[1].contains(".css") || header[1].contains(".woff") || header[1].contains(".ico")) {
            return null;
        } else {
            List<String> result = new ArrayList<>();
            String[] data = header[1].split("/");

            //当链接为根目录时 data的长度就会为0 此时直接添加并返回
            if (data.length == 0) {
                for (String info : Path.payloads) {
                    result.add("GET " + info + " " + header[2]);
                }
                return result;
            }

            //段连接只取前面的一个目录作为字典
            if (data.length <= 2) {
                //添加根目录作为爆破字典
                for (String info : Path.payloads) {
                    result.add("GET " + info + " " + header[2]);
                }
                //添加一级目录再加上字典爆破
                for (String info : Path.payloads) {
                    result.add("GET /" + data[1] + info + " " + header[2]);
                }
            } else {    //长链接取前面两个目录作为爆破字典
                //添加根目录作为爆破字典
                for (String info : Path.payloads) {
                    result.add("GET " + info + " " + header[2]);
                }
                //一级目录加上payload的目录爆破
                for (String info : Path.payloads) {
                    result.add("GET /" + data[1] + info + " " + header[2]);
                }
                //一级目录加上二级目录再加上payload爆破
                for (String info : Path.payloads) {
                    result.add("GET /" + data[1] + "/" + data[2] + info + " " + header[2]);
                }
            }
            return result;
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
        if (data.contains("swagger-ui.css") || data.contains("******") || data.contains("swaggerversion") ||
                data.contains("actuator/info") || data.contains("actuator/health") || data.contains("profiles") ||
                data.contains("\"swagger\"")) {
            return true;
        } else {
            return false;
        }

    }

}
