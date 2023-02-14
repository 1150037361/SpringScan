package ui;

import burp.BurpExtender;
import burp.Path;
import burp.Table;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import tableMode.PathTableMode;
import tableMode.ValueTableMode;
import util.HttpUtil;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import javax.swing.table.TableColumn;
import javax.swing.text.StyleContext;
import java.awt.*;
import java.awt.event.*;
import java.util.Locale;

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

    private PathTableMode pathTableMode;
    private ValueTableMode valueTableMode;

    public MainTab(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        $$$setupUI$$$();
        Init();
    }

    //无参构造
    public MainTab() {
        $$$setupUI$$$();
        pathTableMode = new PathTableMode();
        valueTableMode = new ValueTableMode();
        pathTable.setModel(pathTableMode);
        TableColumn column = pathTable.getColumnModel().getColumn(0);
        column.setPreferredWidth(1);

        valueTable.setModel(valueTableMode);

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

        //回复默认配置
        pathdefaultConfButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getPathTableMode().setDefaultPath();
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

        //回复默认配置

        valuedefaultConfButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.getValueTableMode().setDefaultValue();
            }
        });
    }


//记得在下方的 requestPanel创建处添加下方注释代码
//        requestPanel.addTab("Request",burpExtender.getRequestViewer().getComponent());
//        requestPanel.addTab("Response",burpExtender.getResponseViewer().getComponent());


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
        requestPanel.addTab("Request", burpExtender.getRequestViewer().getComponent());
        requestPanel.addTab("Response", burpExtender.getResponseViewer().getComponent());
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
        configPanel = new JPanel();
        configPanel.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabPanel.addTab("配置信息", configPanel);
        pathPanel = new JPanel();
        pathPanel.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        configPanel.add(pathPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        descriptionPanel = new JPanel();
        descriptionPanel.setLayout(new GridLayoutManager(2, 2, new Insets(10, 30, 0, 0), -1, -1));
        pathPanel.add(descriptionPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        Font label1Font = this.$$$getFont$$$(null, Font.BOLD, 16, label1.getFont());
        if (label1Font != null) label1.setFont(label1Font);
        label1.setForeground(new Color(-39373));
        label1.setText("路径配置");
        descriptionPanel.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        descriptionPanel.add(spacer1, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("此处配置需要遍历的扫描的路径，不建议配置太多，否则会导致内存占用过高问题");
        descriptionPanel.add(label2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathConfigInfoPanel = new JPanel();
        pathConfigInfoPanel.setLayout(new GridLayoutManager(2, 2, new Insets(10, 30, 0, 0), -1, -1));
        pathPanel.add(pathConfigInfoPanel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 2, new Insets(0, 10, 0, 0), -1, -1));
        pathConfigInfoPanel.add(panel1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        pathAddButton = new JButton();
        pathAddButton.setText("Add");
        panel1.add(pathAddButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathTextField = new JTextField();
        panel1.add(pathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        pathConfigInfoPanel.add(panel2, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        pathScrPanel = new JScrollPane();
        panel2.add(pathScrPanel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        pathTable = new JTable();
        pathTable.setPreferredScrollableViewportSize(new Dimension(400, 200));
        pathTable.setUpdateSelectionOnSort(true);
        pathScrPanel.setViewportView(pathTable);
        btPanel = new JPanel();
        btPanel.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(btPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        pathEditButton = new JButton();
        pathEditButton.setText("Edit");
        btPanel.add(pathEditButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathRemoveButton = new JButton();
        pathRemoveButton.setText("Remove");
        btPanel.add(pathRemoveButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathClearButton = new JButton();
        pathClearButton.setText("Clear");
        btPanel.add(pathClearButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathdefaultConfButton = new JButton();
        pathdefaultConfButton.setText("Default Conf");
        btPanel.add(pathdefaultConfButton, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        indexPanel = new JPanel();
        indexPanel.setLayout(new GridLayoutManager(3, 1, new Insets(20, 30, 0, 0), -1, -1));
        configPanel.add(indexPanel, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_NORTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(2, 2, new Insets(10, 0, 0, 0), -1, -1));
        indexPanel.add(panel3, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        Font label3Font = this.$$$getFont$$$(null, Font.BOLD, 16, label3.getFont());
        if (label3Font != null) label3.setFont(label3Font);
        label3.setForeground(new Color(-39373));
        label3.setText("扫描深度配置");
        panel3.add(label3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("配置扫描路径的级数，默认为2级，建议配置为2-3级，多配置可能会导致内存占用过高");
        panel3.add(label4, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        indexPanel.add(panel4, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("扫描级数：");
        panel4.add(label5, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel4.add(spacer2, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        scanIndexBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        defaultComboBoxModel1.addElement("1");
        defaultComboBoxModel1.addElement("2");
        defaultComboBoxModel1.addElement("3");
        defaultComboBoxModel1.addElement("4");
        defaultComboBoxModel1.addElement("5");
        defaultComboBoxModel1.addElement("6");
        scanIndexBox.setModel(defaultComboBoxModel1);
        panel4.add(scanIndexBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JSeparator separator1 = new JSeparator();
        indexPanel.add(separator1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        valuePanel = new JPanel();
        valuePanel.setLayout(new GridLayoutManager(3, 2, new Insets(10, 30, 0, 0), -1, -1));
        configPanel.add(valuePanel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_NORTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        valueConfigInfoPanel = new JPanel();
        valueConfigInfoPanel.setLayout(new GridLayoutManager(2, 2, new Insets(10, 0, 0, 0), -1, -1));
        valuePanel.add(valueConfigInfoPanel, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 2, new Insets(0, 10, 0, 0), -1, -1));
        valueConfigInfoPanel.add(panel5, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        valueAddButton = new JButton();
        valueAddButton.setText("Add");
        panel5.add(valueAddButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valueTextField = new JTextField();
        panel5.add(valueTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(25, -1), null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        valueConfigInfoPanel.add(panel6, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel6.add(panel7, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        valueEditButton = new JButton();
        valueEditButton.setText("Edit");
        panel7.add(valueEditButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valueRemoveButton = new JButton();
        valueRemoveButton.setText("Remove");
        panel7.add(valueRemoveButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valueClearButton = new JButton();
        valueClearButton.setText("Clear");
        panel7.add(valueClearButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        valuedefaultConfButton = new JButton();
        valuedefaultConfButton.setText("Default Conf");
        panel7.add(valuedefaultConfButton, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane2 = new JScrollPane();
        panel6.add(scrollPane2, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_NORTHWEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        valueTable = new JTable();
        valueTable.setPreferredScrollableViewportSize(new Dimension(400, 200));
        scrollPane2.setViewportView(valueTable);
        valueDescriptionPanel = new JPanel();
        valueDescriptionPanel.setLayout(new GridLayoutManager(2, 1, new Insets(10, 0, 0, 0), -1, -1));
        valuePanel.add(valueDescriptionPanel, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_NORTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        Font label6Font = this.$$$getFont$$$(null, Font.BOLD, 16, label6.getFont());
        if (label6Font != null) label6.setFont(label6Font);
        label6.setForeground(new Color(-39373));
        label6.setText("匹配值配置");
        valueDescriptionPanel.add(label6, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label7 = new JLabel();
        label7.setText("此处配置的是上方扫描路径扫描后的结果是否包含该表内的字符串，包含则添加结果，否则不添加");
        valueDescriptionPanel.add(label7, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
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
