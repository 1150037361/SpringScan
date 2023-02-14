package tableMode;

import burp.Path;
import burp.VulData;
import lombok.Data;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
public class PathTableMode extends AbstractTableModel {
    private List<String> pathData;
    private String tableHeader[] = {"Path"};

    public PathTableMode() {
        pathData = new ArrayList<>(Arrays.asList(Path.fullPath));
    }

    @Override
    public int getRowCount() {
        return pathData.size();
    }

    @Override
    public int getColumnCount() {
        return 1;
    }

    @Override
    public String getColumnName(int column) {
        return tableHeader[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        String data = pathData.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return data;
            default:
                return "";
        }
    }

    public void addRow(String data) {
        this.pathData.add(data);
        fireTableRowsInserted(pathData.size(), pathData.size());
    }

    public void editRow(String data, int rowIndex) {
        pathData.set(rowIndex, data);
        fireTableDataChanged();
    }

    public void removeRow(int rowIndex) {
        this.pathData.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
    }

    public void clearRow() {
        this.pathData.clear();
        fireTableRowsDeleted(pathData.size(), pathData.size());
    }

    public void setDefaultPath() {
        pathData = new ArrayList<>(Arrays.asList(Path.fullPath));
        fireTableDataChanged();
    }

    public Boolean contiansUrl(String url) {
        if (pathData == null) {
            return false;
        }
        for (String info : pathData) {
            if (url.equals(info)) {
                return true;
            }
        }
        return false;
    }
}
