import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.IOException;

public class Test {
    public static void main(String[] args) {
        JFrame jf = new JFrame();
        JPanel root1 = new JPanel();
        JPanel root2 = new JPanel(new BorderLayout());

        JPanel requestInfo = new JPanel();


        JLabel lab1 = new JLabel("这是A");

        JLabel lab2 = new JLabel("URL:");

        JTextField urlInfo = new JTextField("请输入链接: http://www.baidu.com",20);
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

        JTextArea data = new JTextArea(10,10);
        data.setEditable(false);
        data.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)){
                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenuItem clean = new JMenuItem(new AbstractAction("clear data") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            data.setText("");
                        }
                    });
                    popupMenu.add(clean);
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
        JScrollPane responseInfo = new JScrollPane(data);


        JButton search = new JButton("搜索");
        search.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new Thread(() ->{
                    String re = doGet(urlInfo.getText());
                    data.append(urlInfo.getText() + "\n");
                }).start();
            }
        });

        requestInfo.add(lab2);
        requestInfo.add(urlInfo);
        requestInfo.add(search);





        JTabbedPane tabPane = new JTabbedPane();


        root1.add(lab1);


        root2.add(requestInfo,BorderLayout.NORTH);
        root2.add(responseInfo,BorderLayout.CENTER);

        tabPane.addTab("A面板", root1);
        tabPane.addTab("B面板", root2);

        jf.add(tabPane);
        jf.setSize(400, 400);
        jf.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jf.setVisible(true);
    }


    public static String doGet(String url) {
        HttpClient httpClient = new HttpClient();
        GetMethod getMethod = new GetMethod(url);
        getMethod.addRequestHeader("accept", "*/*");
        getMethod.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        getMethod.addRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");
        String result = "";
        try {
            int code = httpClient.executeMethod(getMethod);
            if (code == 200) {
                result = getMethod.getResponseBodyAsString();
                System.out.println(result);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

}
