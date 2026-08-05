package exTable;

import burp.BurpExtender;
import entity.ApiData;
import tableMode.ApiTableMode;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import java.util.Comparator;

public class ApiTable extends JTable {
    private BurpExtender burpExtender;
    public ApiTable() {
    }

    public void setBurpExtender(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
    }

    public ApiTable(BurpExtender burpExtender) {
        super(burpExtender.getApiTableMode());
        this.burpExtender = burpExtender;

        //设置排序规则
        TableRowSorter<ApiTableMode> sorter = new TableRowSorter<>(burpExtender.getApiTableMode());
        sorter.setComparator(0, Comparator.comparingInt(o -> Integer.parseInt(o.toString())));
        sorter.setComparator(5, Comparator.comparingInt(o -> Integer.parseInt(o.toString())));

        //开启排序
        setRowSorter(sorter);
    }

    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        int modelRow = convertRowIndexToModel(rowIndex);   // ⭐ 关键一行
        ApiData data = burpExtender.getApiTableMode().getApiData().get(modelRow);
        burpExtender.getApiRequestViewer().setMessage(data.getHttpRequestResponse().getRequest(), true);
        burpExtender.getApiResponseViewer().setMessage(data.getHttpRequestResponse().getResponse(), false);
        burpExtender.setCurrentlyDisplayedItem(data.getHttpRequestResponse());
        super.changeSelection(rowIndex, columnIndex, toggle, extend);
    }
}
