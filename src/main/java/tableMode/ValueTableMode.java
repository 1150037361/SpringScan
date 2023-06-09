package tableMode;

import burp.BurpExtender;
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
    private BurpExtender burpExtender;

    public ValueTableMode() {}
    public ValueTableMode(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
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
        saveConfig();
    }

    public void editRow(String data, int rowIndex) {
        valueData.set(rowIndex, data);
        fireTableDataChanged();
        saveConfig();
    }

    public void clearRow(){
        this.valueData.clear();
        fireTableRowsDeleted(valueData.size(), valueData.size());
        saveConfig();
    }

    public void removeRow(int rowIndex) {
        this.valueData.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
        saveConfig();
    }

    public void setDefaultValue() {
        valueData = new ArrayList<>(Arrays.asList(Path.values));
        fireTableDataChanged();
        saveConfig();
    }

    public void saveConfig() {
        burpExtender.getConfig().put("value",valueData);
        burpExtender.saveConfigToJson();
    }
}
