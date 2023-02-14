package tableMode;

import burp.Path;
import lombok.Data;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
public class ValueTableMode extends AbstractTableModel {
    private List<String> valueData;
    private String tableHeader[] = {"Value"};

    public ValueTableMode() {
        valueData = new ArrayList<>(Arrays.asList(Path.values));
    }
    @Override
    public int getRowCount() {
        return valueData.size();
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
        String data = valueData.get(rowIndex);
        switch (columnIndex){
            case 0:return data;
            default:return "";
        }
    }

    public void addRow(String  data){
        this.valueData.add(data);
        fireTableRowsInserted(valueData.size(), valueData.size());
    }

    public void editRow(String data, int rowIndex) {
        valueData.set(rowIndex, data);
        fireTableDataChanged();
    }

    public void clearRow(){
        this.valueData.clear();
        fireTableRowsDeleted(valueData.size(), valueData.size());
    }

    public void removeRow(int rowIndex) {
        this.valueData.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
    }

    public void setDefaultValue() {
        valueData = new ArrayList<>(Arrays.asList(Path.values));
        fireTableDataChanged();
    }

    public Boolean contiansUrl(String url){
        if (valueData == null){
            return false;
        }
        for (String info: valueData){
            if (url.equals(info)){
                return true;
            }
        }
        return false;
    }
}
