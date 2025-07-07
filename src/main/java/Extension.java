import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class Extension implements BurpExtension {
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("VulCheck");

        // 创建主标签页
        JTabbedPane extensionTabs = new JTabbedPane();
        extensionTabs.addTab("Statistics", constructStatisticsPanel());
        extensionTabs.addTab("Log", constructLogPanel());

        // 注册扩展标签页
        api.userInterface().registerSuiteTab("VulCheck", extensionTabs);
    }

    private JPanel constructStatisticsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        String[] columns = {"Enable", "Checklist", "Status", "VulResult"};
        DefaultTableModel model = new DefaultTableModel(columns, 0);
        model.addRow(new Object[]{true, "SQL Injection", "3 scanning, 25 scanned", "0"});
        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setCellRenderer(new CheckBoxRenderer());
        table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JCheckBox()));
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private JPanel constructLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // 过滤器面板
        JPanel filterPanel = new JPanel();
        JComboBox<String> columnSelector = new JComboBox<>(new String[]{"URL", "Checktype", "Result"});
        JTextField keywordField = new JTextField(20);
        JButton filterButton = new JButton("Apply Filter");
        filterPanel.add(new JLabel("Filter by:"));
        filterPanel.add(columnSelector);
        filterPanel.add(keywordField);
        filterPanel.add(filterButton);

        // 日志表格
        String[] columns = {"URL", "Checktype", "Result"};
        DefaultTableModel model = new DefaultTableModel(columns, 0);
        model.addRow(new Object[]{"https://example.com/v1/config", "SQL Injection", "Issues"});
        JTable table = new JTable(model);
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.setAutoCreateRowSorter(true);

        // 导出按钮
        JButton exportButton = new JButton("Export to XLSX");
        exportButton.addActionListener(e -> exportToXLSX(model));

        // ScanDetail区域
        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.addTab("Request", api.userInterface().createHttpRequestEditor().uiComponent());
        detailTabs.addTab("Response", api.userInterface().createHttpResponseEditor().uiComponent());
        detailTabs.addTab("Analysis", new JScrollPane(new JTextArea("Analysis details here")));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailTabs);
        splitPane.setDividerLocation(300);

        // 过滤器逻辑
        filterButton.addActionListener(e -> {
            String keyword = keywordField.getText();
            int columnIndex = columnSelector.getSelectedIndex();
            if (keyword.trim().isEmpty()) {
                sorter.setRowFilter(null);
            } else {
                sorter.setRowFilter(RowFilter.regexFilter(keyword, columnIndex));
            }
        });

        // 行选择监听器
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow >= 0) {
                    // 更新ScanDetail内容（需替换为实际数据）
                    api.userInterface().createHttpRequestEditor().setRequest(null);
                    api.userInterface().createHttpResponseEditor().setResponse(null);
                }
            }
        });

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(filterPanel, BorderLayout.NORTH);
        topPanel.add(exportButton, BorderLayout.SOUTH);
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private void exportToXLSX(DefaultTableModel model) {
        // 使用Apache POI实现XLSX导出（需添加依赖）
        // 示例代码省略，需实现实际导出逻辑
    }

    private static class CheckBoxRenderer extends JCheckBox implements TableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            setSelected((Boolean) value);
            return this;
        }
    }
}