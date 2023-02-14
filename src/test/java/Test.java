import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.IOException;

public class Test {
    private JFrame frame;
    private JButton button;
    private JLabel label;
    private int value = 0;

    public Test() {
        frame = new JFrame("Example");
        button = new JButton("Change Value");
        label = new JLabel("Value: " + value);

        frame.setLayout(new FlowLayout());
        frame.add(button);
        frame.add(label);

        button.addActionListener(e -> {
            String input = JOptionPane.showInputDialog(frame, "Enter a new value:", value);
            if (input != null) {
                try {
                    value = Integer.parseInt(input);
                    label.setText("Value: " + value);
                } catch (NumberFormatException ex) {
                    JOptionPane.showMessageDialog(frame, "Invalid input.");
                }
            }
        });

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    public static void main(String[] args) {
        new Test();
    }
}
