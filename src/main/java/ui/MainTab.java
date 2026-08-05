package ui;

import burp.IHttpRequestResponse;
import entity.ApiData;
import exTable.ApiTable;
import burp.BurpExtender;
import exTable.Table;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import tableMode.PathTableMode;
import tableMode.ValueTableMode;
import util.HttpRequestResponse;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import javax.swing.table.TableColumn;
import javax.swing.text.StyleContext;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

public class MainTab {
    private BurpExtender burpExtender;
    private JTabbedPane tabPanel;
    private JPanel rootPanel;
    private Table vulTable;
    private JTabbedPane requestPanel;
    private JSplitPane bdScanPanel;
    private JPanel configPanel;
    private JPanel pathPanel;
    private JPanel indexPanel;
    private JTable pathTable;
    private JButton pathEditButton;
    private JButton pathRemoveButton;
    private JButton pathClearButton;
    public JComboBox scanIndexBox;
    private JPanel btPanel;
    private JScrollPane pathScrPanel;
    private JPanel pathConfigInfoPanel;
    private JPanel descriptionPanel;
    private JButton valueEditButton;
    private JButton valueRemoveButton;
    private JButton valueClearButton;
    private JTable valueTable;
    private JPanel valuePanel;
    private JButton pathAddButton;
    private JButton valueAddButton;
    private JTextField valueTextField;
    private JTextField pathTextField;
    private JPanel valueDescriptionPanel;
    private JPanel valueConfigInfoPanel;
    private JButton pathdefaultConfButton;
    private JButton valuedefaultConfButton;
    public JCheckBox scanEnableCheckBox;
    public JCheckBox scanSlowCheckBox;
    private JSplitPane analysisJsPanel;
    private JTabbedPane apiRequestInfoPanel;
    private ApiTable apiInfoTable;
    private JButton pathAddFileButton;
    private JButton valueAddFileButton;
    private JPanel analysisPanel;
    private JButton testUrlButton;
    private JTextField urlTextField;
    private JScrollPane analysisJscrollPanel;
    private JButton setPathButton;
    public JTextField timeTextField;

    private PathTableMode pathTableMode;
    private ValueTableMode valueTableMode;

    public MainTab(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        $$$setupUI$$$();
        Init();
    }

    //无参构造
    public MainTab() throws IOException, URISyntaxException {
        $$$setupUI$$$();
        pathTableMode = new PathTableMode();
        valueTableMode = new ValueTableMode();
        pathTable.setModel(pathTableMode);
        TableColumn column = pathTable.getColumnModel().getColumn(0);
        column.setPreferredWidth(1);

        valueTable.setModel(valueTableMode);


        /**
         * 接口分析初始化配置
         */
        String defaultValue = "请输入拼接前的URL，如接口地址为：http://xxx.com/api/getuser,输入http://xxx.com即可";
        urlTextField.setForeground(Color.gray);
        urlTextField.setText(defaultValue);
        urlTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (urlTextField.getText().equals(defaultValue)) {
                    urlTextField.setText("");
                    urlTextField.setForeground(Color.black);
                }
                super.focusGained(e);
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (urlTextField.getText().isEmpty()) {
                    urlTextField.setForeground(Color.gray);
                    urlTextField.setText(defaultValue);
                }
            }
        });

        /**
         * -----------------------------------------------------------------------------------------------------
         * 路径表格相关的监听
         * -----------------------------------------------------------------------------------------------------
         */
        //路径表格添加数据按钮监听
        pathAddButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                pathTableMode.addRow(pathTextField.getText());
            }
        });

        //路径表格清除全部数据按钮监听
        pathClearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                pathTableMode.clearRow();
            }
        });

        //路径表格清除某一行数据监听
        pathRemoveButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                pathTableMode.removeRow(pathTable.getSelectedRow());
            }
        });

        //路径表格文件添加
        pathAddFileButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    // 打开文件选择对话框
                    JFileChooser fileChooser = new JFileChooser();
                    int result = fileChooser.showOpenDialog(null);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        // 选择了文件，读取文件内容并显示在文本区域中
                        File selectedFile = fileChooser.getSelectedFile();
                        BufferedReader reader = new BufferedReader(new FileReader(selectedFile));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            System.out.print(line);
                            pathTableMode.addRow(line);
                        }
                        reader.close();
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Error reading file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        //路径表格修改某一行数据
        pathEditButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String value = "";
                String input = JOptionPane.showInputDialog(null, "请输入修改后的值:", value);
                if (input != null) {
                    try {
                        pathTableMode.editRow(input, pathTable.getSelectedRow());
                    } catch (NumberFormatException ex) {
                        JOptionPane.showMessageDialog(null, "输入错误！！");
                    }
                }
            }
        });

        /**
         * ----------------------------------------------------------------------------------------------------
         * 数值表格相关的监听
         * ----------------------------------------------------------------------------------------------------
         */
        valueAddButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                valueTableMode.addRow(valueTextField.getText());
            }
        });

        //路径表格清除全部数据按钮监听
        valueClearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                valueTableMode.clearRow();
            }
        });

        //路径表格清除某一行数据监听
        valueRemoveButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                valueTableMode.removeRow(valueTable.getSelectedRow());
            }
        });

        //路径表格修改某一行数据
        valueEditButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String value = "";
                String input = JOptionPane.showInputDialog(null, "请输入修改后的值:", value);
                if (input != null) {
                    try {
                        valueTableMode.editRow(input, valueTable.getSelectedRow());
                    } catch (NumberFormatException ex) {
                        JOptionPane.showMessageDialog(null, "输入错误！！");
                    }
                }
            }
        });
    }


    /**
     * burp的初始化方法，无参构造就直接在内部实现
     */
    public void Init() {
        pathTable.setModel(burpExtender.getPathTableMode());
        valueTable.setModel(burpExtender.getValueTableMode());
        scanIndexBox.setSelectedIndex(1);

//        vulTable.setBurpExtender(burpExtender);
//        apiInfoTable.setBurpExtender(burpExtender);
//        apiInfoTable.setAutoCreateRowSorter(true);

        requestPanel.addTab("Request", burpExtender.getRequestViewer().getComponent());
        requestPanel.addTab("Response", burpExtender.getResponseViewer().getComponent());

        apiRequestInfoPanel.addTab("Request", burpExtender.getApiRequestViewer().getComponent());
        apiRequestInfoPanel.addTab("Response", burpExtender.getApiResponseViewer().getComponent());


        //表格加入一键清理
        vulTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    Point clickPoint = e.getPoint();
                    int rowAtPoint = vulTable.rowAtPoint(clickPoint);
                    if (rowAtPoint == -1) {
                        return;
                    }

                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenuItem clean = new JMenuItem(new AbstractAction("clear data") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            burpExtender.getResponseViewer().setMessage("".getBytes(), false);
                            burpExtender.getRequestViewer().setMessage("".getBytes(), false);
                            burpExtender.getVulTableMode().clearRow();
                        }
                    });
                    popupMenu.add(clean);
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        /**
         * 接口分析初始化配置
         */
        String defaultValue = "请输入基础路径，默认为接口文档的basepath。例：api文档中路径为/test/gettest，而请求为xxx.com/api/test/gettest 输入/api即可";
        urlTextField.setForeground(Color.gray);
        urlTextField.setText(defaultValue);
        urlTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (urlTextField.getText().equals(defaultValue)) {
                    urlTextField.setText("");
                    urlTextField.setForeground(Color.black);
                }
                super.focusGained(e);
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (urlTextField.getText().isEmpty()) {
                    urlTextField.setForeground(Color.gray);
                    urlTextField.setText(defaultValue);
                }
            }
        });

        //设置基础路径按钮监听
        setPathButton.addActionListener(new AbstractAction() {

            @Override
            public void actionPerformed(ActionEvent e) {
                List<ApiData> apiData = burpExtender.getApiTableMode().getApiData();
                if (!urlTextField.getText().equals(defaultValue)) {
                    for (ApiData data : apiData) {
                        String newPath = urlTextField.getText() + data.getPath();
                        data.getHttpRequestResponse().setPath(newPath);
                        data.setUrl(data.getHttpRequestResponse().getPath());
                        SwingUtilities.invokeLater(() -> burpExtender.getApiTableMode().fireTableDataChanged());
                    }
                }
            }
        });


        //遍历api接口按钮监听
        testUrlButton.addActionListener(new AbstractAction() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // 在后台线程中发送请求，避免阻塞 Swing 事件线程导致界面卡死
                new Thread(() -> {
                    List<ApiData> apiData = burpExtender.getApiTableMode().getApiData();
                    for (ApiData apiData1 : apiData) {
                        IHttpRequestResponse resp = burpExtender.getCallbacks().makeHttpRequest(apiData1.getHttpRequestResponse().getHttpService(), apiData1.getHttpRequestResponse().getRequest());

                        // 网络层请求失败时 response 为 null，跳过该请求避免空指针
                        if (resp == null || resp.getResponse() == null) {
                            continue;
                        }
                        apiData1.setStatusCode(String.valueOf(burpExtender.helpers.analyzeResponse(resp.getResponse()).getStatusCode()));
                        apiData1.setResponseSize(String.valueOf(resp.getResponse().length));
                        apiData1.setHttpRequestResponse(new HttpRequestResponse(resp, burpExtender));
                        // 回到事件线程刷新表格，让状态码/响应大小列更新
                        SwingUtilities.invokeLater(() -> burpExtender.getApiTableMode().fireTableDataChanged());
                    }
                }).start();
            }
        });


        /**
         * -----------------------------------------------------------------------------------------------------
         * 路径表格相关的监听
         * -----------------------------------------------------------------------------------------------------
         */
        //路径表格添加数据按钮监听
        pathAddButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getPathTableMode().addRow(pathTextField.getText());
            }
        });

        //路径表格清除全部数据按钮监听
        pathClearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getPathTableMode().clearRow();
            }
        });

        //路径表格清除某一行数据监听
        pathRemoveButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getPathTableMode().removeRow(pathTable.getSelectedRow());
            }
        });

        //路径表格修改某一行数据
        pathEditButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String value = "";
                String input = JOptionPane.showInputDialog(null, "请输入修改后的值:", value);
                if (input != null) {
                    try {
                        burpExtender.getPathTableMode().editRow(input, pathTable.getSelectedRow());
                    } catch (NumberFormatException ex) {
                        JOptionPane.showMessageDialog(null, "输入错误！！");
                    }
                }
            }
        });

        //恢复默认配置
        pathdefaultConfButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getPathTableMode().setDefaultPath();
            }
        });

        //路径表格文件添加
        pathAddFileButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    // 打开文件选择对话框
                    JFileChooser fileChooser = new JFileChooser();
                    int result = fileChooser.showOpenDialog(null);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        // 选择了文件，读取文件内容并显示在文本区域中
                        File selectedFile = fileChooser.getSelectedFile();
                        BufferedReader reader = new BufferedReader(new FileReader(selectedFile));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            System.out.print(line);
                            burpExtender.getPathTableMode().addRow(line);
                        }
                        reader.close();
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Error reading file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        /**
         * ----------------------------------------------------------------------------------------------------
         * 数值表格相关的监听
         * ----------------------------------------------------------------------------------------------------
         */
        valueAddButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getValueTableMode().addRow(valueTextField.getText());
            }
        });

        //路径表格清除全部数据按钮监听
        valueClearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getValueTableMode().clearRow();
            }
        });

        //路径表格清除某一行数据监听
        valueRemoveButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getValueTableMode().removeRow(valueTable.getSelectedRow());
            }
        });

        //路径表格修改某一行数据
        valueEditButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String value = "";
                String input = JOptionPane.showInputDialog(null, "请输入修改后的值:", value);
                if (input != null) {
                    try {
                        burpExtender.getValueTableMode().editRow(input, valueTable.getSelectedRow());
                    } catch (NumberFormatException ex) {
                        JOptionPane.showMessageDialog(null, "输入错误！！");
                    }
                }
            }
        });

        //恢复默认配置
        valuedefaultConfButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getValueTableMode().setDefaultValue();
            }
        });

        //数值文件添加
        valueAddFileButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    // 打开文件选择对话框
                    JFileChooser fileChooser = new JFileChooser();
                    int result = fileChooser.showOpenDialog(null);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        // 选择了文件，读取文件内容并显示在文本区域中
                        File selectedFile = fileChooser.getSelectedFile();
                        BufferedReader reader = new BufferedReader(new FileReader(selectedFile));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            System.out.print(line);
                            burpExtender.getValueTableMode().addRow(line);
                        }
                        reader.close();
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Error reading file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
    }


//记得在下方的 vultable创建处加上默认参数burpExtender
//            apiInfoTable = new ApiTable(burpExtender);
//            vulTable = new Table(burpExtender);


    public static void main(String[] args) throws IOException, URISyntaxException {
        JFrame frame = new JFrame("MainTab");
        frame.setContentPane(new MainTab().rootPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
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
        tabPanel.addTab("扫描信息", bdScanPanel);
        final JScrollPane scrollPane1 = new JScrollPane();
        bdScanPanel.setLeftComponent(scrollPane1);
        vulTable = new Table(burpExtender);
        scrollPane1.setViewportView(vulTable);
        requestPanel = new JTabbedPane();
        bdScanPanel.setRightComponent(requestPanel);
        analysisPanel = new JPanel();
        analysisPanel.setLayout(new BorderLayout(0, 0));
        tabPanel.addTab("接口分析", analysisPanel);
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 4, new Insets(10, 10, 10, 10), -1, -1));
        analysisPanel.add(panel1, BorderLayout.NORTH);
        testUrlButton = new JButton();
        testUrlButton.setText("批量测试");
        panel1.add(testUrlButton, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("请求拼接URL：");
        panel1.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        urlTextField = new JTextField();
        urlTextField.setText("");
        panel1.add(urlTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        setPathButton = new JButton();
        setPathButton.setText("修改基础路径");
        panel1.add(setPathButton, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        analysisJsPanel = new JSplitPane();
        analysisJsPanel.setOrientation(0);
        analysisPanel.add(analysisJsPanel, BorderLayout.CENTER);
        analysisJscrollPanel = new JScrollPane();
        analysisJsPanel.setLeftComponent(analysisJscrollPanel);
        apiInfoTable = new ApiTable(burpExtender);
        analysisJscrollPanel.setViewportView(apiInfoTable);
        apiRequestInfoPanel = new JTabbedPane();
        analysisJsPanel.setRightComponent(apiRequestInfoPanel);
        configPanel = new JPanel();
        configPanel.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabPanel.addTab("配置信息", configPanel);
        pathPanel = new JPanel();
        pathPanel.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        configPanel.add(pathPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        descriptionPanel = new JPanel();
        descriptionPanel.setLayout(new GridLayoutManager(2, 2, new Insets(10, 30, 0, 0), -1, -1));
        pathPanel.add(descriptionPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        Font label2Font = this.$$$getFont$$$(null, Font.BOLD, 16, label2.getFont());
        if (label2Font != null) label2.setFont(label2Font);
        label2.setForeground(new Color(-39373));
        label2.setText("路径配置");
        descriptionPanel.add(label2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        descriptionPanel.add(spacer1, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("此处配置需要遍历的扫描的路径，不建议配置太多，否则会导致内存占用过高问题");
        descriptionPanel.add(label3, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathConfigInfoPanel = new JPanel();
        pathConfigInfoPanel.setLayout(new GridLayoutManager(2, 2, new Insets(10, 30, 0, 0), -1, -1));
        pathPanel.add(pathConfigInfoPanel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 10, 0, 0), -1, -1));
        pathConfigInfoPanel.add(panel2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        pathAddButton = new JButton();
        pathAddButton.setText("添加");
        panel2.add(pathAddButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathTextField = new JTextField();
        panel2.add(pathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        pathConfigInfoPanel.add(panel3, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        pathScrPanel = new JScrollPane();
        panel3.add(pathScrPanel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        pathTable = new JTable();
        pathTable.setPreferredScrollableViewportSize(new Dimension(400, 200));
        pathTable.setUpdateSelectionOnSort(true);
        pathScrPanel.setViewportView(pathTable);
        btPanel = new JPanel();
        btPanel.setLayout(new GridLayoutManager(5, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel3.add(btPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        pathEditButton = new JButton();
        pathEditButton.setText("编辑");
        btPanel.add(pathEditButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathRemoveButton = new JButton();
        pathRemoveButton.setText("删除");
        btPanel.add(pathRemoveButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathClearButton = new JButton();
        pathClearButton.setText("清空");
        btPanel.add(pathClearButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathdefaultConfButton = new JButton();
        pathdefaultConfButton.setText("默认配置");
        btPanel.add(pathdefaultConfButton, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathAddFileButton = new JButton();
        pathAddFileButton.setText("从文件加载");
        btPanel.add(pathAddFileButton, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        indexPanel = new JPanel();
        indexPanel.setLayout(new GridLayoutManager(3, 1, new Insets(20, 30, 10, 0), -1, -1));
        configPanel.add(indexPanel, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_NORTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(2, 2, new Insets(10, 0, 0, 0), -1, -1));
        indexPanel.add(panel4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        Font label4Font = this.$$$getFont$$$(null, Font.BOLD, 16, label4.getFont());
        if (label4Font != null) label4.setFont(label4Font);
        label4.setForeground(new Color(-39373));
        label4.setText("扫描配置");
        panel4.add(label4, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("配置扫描路径的级数，默认为2级，建议配置为2-3级，多配置可能会导致内存占用过高，慢速模式在目标有相关云waf下开启，避免被封IP");
        panel4.add(label5, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(3, 5, new Insets(0, 0, 0, 0), -1, -1));
        indexPanel.add(panel5, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("扫描级数：");
        panel5.add(label6, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel5.add(spacer2, new GridConstraints(0, 2, 1, 3, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        scanIndexBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        defaultComboBoxModel1.addElement("1");
        defaultComboBoxModel1.addElement("2");
        defaultComboBoxModel1.addElement("3");
        defaultComboBoxModel1.addElement("4");
        defaultComboBoxModel1.addElement("5");
        defaultComboBoxModel1.addElement("6");
        scanIndexBox.setModel(defaultComboBoxModel1);
        panel5.add(scanIndexBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label7 = new JLabel();
        label7.setText("被动扫描：");
        panel5.add(label7, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        scanEnableCheckBox = new JCheckBox();
        scanEnableCheckBox.setSelected(true);
        scanEnableCheckBox.setText("启动");
        panel5.add(scanEnableCheckBox, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label8 = new JLabel();
        label8.setText("慢速模式：");
        panel5.add(label8, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        scanSlowCheckBox = new JCheckBox();
        scanSlowCheckBox.setText("启动");
        panel5.add(scanSlowCheckBox, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label9 = new JLabel();
        label9.setText("延迟设置(毫秒)：");
        panel5.add(label9, new GridConstraints(2, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        timeTextField = new JTextField();
        timeTextField.setText("500");
        panel5.add(timeTextField, new GridConstraints(2, 3, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JSeparator separator1 = new JSeparator();
        indexPanel.add(separator1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        valuePanel = new JPanel();
        valuePanel.setLayout(new GridLayoutManager(3, 2, new Insets(10, 30, 0, 0), -1, -1));
        configPanel.add(valuePanel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_NORTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        valueConfigInfoPanel = new JPanel();
        valueConfigInfoPanel.setLayout(new GridLayoutManager(2, 2, new Insets(10, 0, 0, 0), -1, -1));
        valuePanel.add(valueConfigInfoPanel, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new GridLayoutManager(1, 2, new Insets(0, 10, 0, 0), -1, -1));
        valueConfigInfoPanel.add(panel6, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        valueAddButton = new JButton();
        valueAddButton.setText("添加");
        panel6.add(valueAddButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valueTextField = new JTextField();
        panel6.add(valueTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(25, -1), null, 0, false));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        valueConfigInfoPanel.add(panel7, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new GridLayoutManager(5, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel7.add(panel8, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        valueEditButton = new JButton();
        valueEditButton.setText("编辑");
        panel8.add(valueEditButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valueRemoveButton = new JButton();
        valueRemoveButton.setText("删除");
        panel8.add(valueRemoveButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valueClearButton = new JButton();
        valueClearButton.setText("清空");
        panel8.add(valueClearButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valuedefaultConfButton = new JButton();
        valuedefaultConfButton.setText("默认配置");
        panel8.add(valuedefaultConfButton, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valueAddFileButton = new JButton();
        valueAddFileButton.setText("从文件添加");
        panel8.add(valueAddFileButton, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane2 = new JScrollPane();
        panel7.add(scrollPane2, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        valueTable = new JTable();
        valueTable.setPreferredScrollableViewportSize(new Dimension(400, 200));
        scrollPane2.setViewportView(valueTable);
        valueDescriptionPanel = new JPanel();
        valueDescriptionPanel.setLayout(new GridLayoutManager(2, 1, new Insets(10, 0, 0, 0), -1, -1));
        valuePanel.add(valueDescriptionPanel, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_NORTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label10 = new JLabel();
        Font label10Font = this.$$$getFont$$$(null, Font.BOLD, 16, label10.getFont());
        if (label10Font != null) label10.setFont(label10Font);
        label10.setForeground(new Color(-39373));
        label10.setText("匹配值配置");
        valueDescriptionPanel.add(label10, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label11 = new JLabel();
        label11.setText("此处配置的是上方扫描路径扫描后的结果是否包含该表内的字符串，包含则添加结果，否则不添加");
        valueDescriptionPanel.add(label11, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JSeparator separator2 = new JSeparator();
        valuePanel.add(separator2, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final Spacer spacer3 = new Spacer();
        configPanel.add(spacer3, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    private Font $$$getFont$$$(String fontName, int style, int size, Font currentFont) {
        if (currentFont == null) return null;
        String resultName;
        if (fontName == null) {
            resultName = currentFont.getName();
        } else {
            Font testFont = new Font(fontName, Font.PLAIN, 10);
            if (testFont.canDisplay('a') && testFont.canDisplay('1')) {
                resultName = fontName;
            } else {
                resultName = currentFont.getName();
            }
        }
        Font font = new Font(resultName, style >= 0 ? style : currentFont.getStyle(), size >= 0 ? size : currentFont.getSize());
        boolean isMac = System.getProperty("os.name", "").toLowerCase(Locale.ENGLISH).startsWith("mac");
        Font fontWithFallback = isMac ? new Font(font.getFamily(), font.getStyle(), font.getSize()) : new StyleContext().getFont(font.getFamily(), font.getStyle(), font.getSize());
        return fontWithFallback instanceof FontUIResource ? fontWithFallback : new FontUIResource(fontWithFallback);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }

}
