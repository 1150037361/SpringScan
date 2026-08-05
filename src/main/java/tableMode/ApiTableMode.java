package tableMode;

import burp.BurpExtender;
import entity.ApiData;
import lombok.Data;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

@Data
public class ApiTableMode extends AbstractTableModel {
    private List<ApiData> apiData = new ArrayList<ApiData>();
    private String tableHeader[] = {"#","请求方法","API地址","接口描述","状态码","响应大小"};
    @Override
    public int getRowCount() {
        return apiData.size();
    }

    @Override
    public int getColumnCount() {
        return 6;
    }

    @Override
    public String getColumnName(int column) {
        return tableHeader[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ApiData data = apiData.get(rowIndex);
        switch (columnIndex){
            case 0:return String.valueOf(rowIndex + 1);
            case 1:return data.getMethod();
            case 2:return data.getUrl();
            case 3:return data.getSummary();
            case 4:return data.getStatusCode();
            case 5:return data.getResponseSize();
            default:return "";
        }
    }


    public void addRow(ApiData data){
        this.apiData.add(data);
        fireTableDataChanged();
    }

    public void clearRow(){
        this.apiData.clear();
        fireTableDataChanged();
    }

    public Boolean contiansUrl(String url){
        if (apiData == null){
            return false;
        }
        for (ApiData info: apiData){
            if (url.equals(info.getUrl())){
                return true;
            }
        }
        return false;
    }
}
