package burp;

import lombok.Data;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

@Data
public class TableMode extends AbstractTableModel {
    private BurpExtender burpExtender;
    private List<VulData> vulData = new ArrayList<VulData>();
    private String tableHeader[] = {"#","URL","ResultSize","Issue"};
    @Override
    public int getRowCount() {
        return vulData.size();
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public String getColumnName(int column) {
        return tableHeader[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        VulData data = vulData.get(rowIndex);
        switch (columnIndex){
            case 0:return String.valueOf(rowIndex);
            case 1:return data.getUrl();
            case 2:return data.getSize();
            case 3:return data.getIssue();
            default:return "";
        }
    }

    public void addRow(VulData data){
        this.vulData.add(data);
        fireTableRowsInserted(vulData.size(),vulData.size());
    }

    public void clearRow(){
        this.vulData.clear();
        fireTableRowsDeleted(vulData.size(),vulData.size());
    }

    public Boolean contiansUrl(String url){
        if (vulData == null){
            return false;
        }
        for (VulData info: vulData){
            if (url.equals(info.getUrl())){
                return true;
            }
        }
        return false;
    }

    //public Boolean
}
