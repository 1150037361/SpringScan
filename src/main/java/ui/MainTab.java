package ui;

import burp.BurpExtender;
import burp.Path;
import burp.Table;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import util.HttpUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class MainTab {
    private BurpExtender burpExtender;
    private JTabbedPane tabPanel;
    private JPanel rootPanel;
    private Table vulTable;
    private JTabbedPane requestPanel;
    private JTextField urlInfo;
    private JButton search;
    private JTextArea resultData;
    private JProgressBar proccessInfo;
    private JLabel labUrl;
    private JScrollPane textPanel;
    private JLabel labProccess;
    private JPanel searchPanel;
    private JSplitPane bdScanPanel;
    private JPanel zdScanPanel;

    public MainTab(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        $$$setupUI$$$();

        //表格加入一键清理
        vulTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    Point clickPoint = e.getPoint();
                    int rowAtPoint = vulTable.rowAtPoint(clickPoint);
                    if (rowAtPoint == -1){
                        return;
                    }

                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenuItem clean = new JMenuItem(new AbstractAction("clear data") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            burpExtender.getTableMode().clearRow();
                        }
                    });
                    popupMenu.add(clean);
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        //输入框添加消息提示
        urlInfo.setForeground(Color.gray);
        urlInfo.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if (urlInfo.getText().equals("请输入链接: http://www.baidu.com")) {
                    urlInfo.setText("");
                    urlInfo.setForeground(Color.black);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (urlInfo.getText().equals("")) {
                    urlInfo.setForeground(Color.gray); //将提示文字设置为灰色
                    urlInfo.setText("请输入链接: http://www.baidu.com");     //显示提示文字
                }
            }
        });

        //按钮添加监听
        this.search.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                scanBurpApi();
            }
        });


        //返回框添加右键的一键清理,以及禁止编辑
        resultData.setEditable(false);
        this.resultData.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenuItem clean = new JMenuItem(new AbstractAction("clear data") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            resultData.setText("");
                        }
                    });
                    popupMenu.add(clean);
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        //进度条设置
        proccessInfo.setMinimum(0);
        proccessInfo.setMaximum(Path.fullPath.length);
        proccessInfo.setStringPainted(true);
    }

    //无参构造
    public MainTab() {
        /**
         * 被动扫描相关设置
         */


        /**
         * 主动扫描相关设置
         */
        //输入框添加消息提示
        urlInfo.setForeground(Color.gray);
        urlInfo.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if (urlInfo.getText().equals("请输入链接: http://www.baidu.com")) {
                    urlInfo.setText("");
                    urlInfo.setForeground(Color.black);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (urlInfo.getText().equals("")) {
                    urlInfo.setForeground(Color.gray); //将提示文字设置为灰色
                    urlInfo.setText("请输入链接: http://www.baidu.com");     //显示提示文字
                }
            }
        });

        //按钮添加监听
        this.search.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                scanBurpApi();
            }
        });


        //返回框添加右键的一键清理,以及禁止编辑
        resultData.setEditable(false);
        this.resultData.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenuItem clean = new JMenuItem(new AbstractAction("clear data") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            resultData.setText("");
                        }
                    });
                    popupMenu.add(clean);
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        //进度条设置
        proccessInfo.setMinimum(0);
        proccessInfo.setMaximum(Path.fullPath.length);
        proccessInfo.setStringPainted(true);
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("MainTab");
        frame.setContentPane(new MainTab().rootPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
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



    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        rootPanel = new JPanel();
        rootPanel.setLayout(new BorderLayout(0, 0));
        tabPanel = new JTabbedPane();
        rootPanel.add(tabPanel, BorderLayout.CENTER);
        bdScanPanel = new JSplitPane();
        bdScanPanel.setContinuousLayout(false);
        bdScanPanel.setOrientation(0);
        tabPanel.addTab("被动扫描", bdScanPanel);
        final JScrollPane scrollPane1 = new JScrollPane();
        bdScanPanel.setLeftComponent(scrollPane1);
        vulTable = new Table(burpExtender);
        scrollPane1.setViewportView(vulTable);
        requestPanel = new JTabbedPane();
        requestPanel.addTab("Request",burpExtender.getRequestViewer().getComponent());
        requestPanel.addTab("Response",burpExtender.getResponseViewer().getComponent());
        bdScanPanel.setRightComponent(requestPanel);
        zdScanPanel = new JPanel();
        zdScanPanel.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabPanel.addTab("主动扫描", zdScanPanel);
        searchPanel = new JPanel();
        searchPanel.setLayout(new GridLayoutManager(1, 3, new Insets(8, 5, 4, 5), -1, -1));
        zdScanPanel.add(searchPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        labUrl = new JLabel();
        labUrl.setText("URL：");
        searchPanel.add(labUrl, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        urlInfo = new JTextField();
        searchPanel.add(urlInfo, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        search = new JButton();
        search.setText("start");
        searchPanel.add(search, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        textPanel = new JScrollPane();
        zdScanPanel.add(textPanel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        resultData = new JTextArea();
        textPanel.setViewportView(resultData);
        proccessInfo = new JProgressBar();
        zdScanPanel.add(proccessInfo, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        labProccess = new JLabel();
        labProccess.setText("0/0");
        zdScanPanel.add(labProccess, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }

    public void testButton() {
        resultData.append("test button\n");
    }

    public void scanBurpApi() {
        String url = urlInfo.getText();
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }

        String finalUrl = url;
        new Thread(() -> {
            for (int i = 0; i < Path.fullPath.length; i++) {
                String result = HttpUtil.doGet(finalUrl + Path.fullPath[i]);

                //进度条设置
                proccessInfo.setValue(i + 1);
                labProccess.setText(String.valueOf(i + 1) + "/" + String.valueOf(proccessInfo.getMaximum()));

                //判断是否符合POC
                if (isGood(result.toLowerCase())) {
                    resultData.append(finalUrl + Path.fullPath[i] + "\n");
                }
            }
        }).start();
    }

}
