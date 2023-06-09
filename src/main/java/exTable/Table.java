package exTable;

import burp.BurpExtender;
import entity.VulData;

import javax.swing.*;

/**
 * 重写 JTable里的changeSelection方法
 * 同时接收BurpExtender对象便于传值
 */
public class Table extends JTable {
    private BurpExtender burpExtender;
    public Table() {
    }

    public Table(BurpExtender burpExtender) {
        super(burpExtender.getVulTableMode());
        this.burpExtender = burpExtender;
    }

    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        VulData data = burpExtender.getVulTableMode().getVulData().get(rowIndex);
        burpExtender.getRequestViewer().setMessage(data.getIHttpRequestResponse().getRequest(), true);
        burpExtender.getResponseViewer().setMessage(data.getIHttpRequestResponse().getResponse(), false);
        burpExtender.setCurrentlyDisplayedItem(data.getIHttpRequestResponse());
        super.changeSelection(rowIndex, columnIndex, toggle, extend);
    }
}
