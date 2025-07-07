package com.vulcheck.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ExtensionUI {
    private final MontoyaApi api;
    private final DefaultTableModel logTableModel;
    private final List<HttpRequestResponse> requestResponses;

    public ExtensionUI(MontoyaApi api) {
        this.api = api;
        this.logTableModel = new DefaultTableModel(new String[]{"URL", "Checktype", "Result"}, 0);
        this.requestResponses = new ArrayList<>();
    }

    public void initialize() {
        JTabbedPane extensionTabs = new JTabbedPane();
        extensionTabs.addTab("Statistics", constructStatisticsPanel());
        extensionTabs.addTab("Log", constructLogPanel());
        api.userInterface().registerSuiteTab("VulCheck", extensionTabs);
    }

    private JPanel constructStatisticsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        String[] columns = {"Enable", "Checklist", "Status", "VulResult"};
        DefaultTableModel model = new DefaultTableModel(columns, 0);
        model.addRow(new Object[]{true, "Reverse Tabnabbing", "0 scanning, 0 scanned", "0"});
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
        JTable table = new JTable(logTableModel);
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(logTableModel);
        table.setRowSorter(sorter);
        table.setAutoCreateRowSorter(true);

        // 导出按钮
        JButton exportButton = new JButton("Export to XLSX");
        exportButton.addActionListener(e -> exportToXLSX(table));

        // ScanDetail区域
        JTabbedPane detailTabs = new JTabbedPane();
        var requestEditor = api.userInterface().createHttpRequestEditor();
        var responseEditor = api.userInterface().createHttpResponseEditor();
        JTextArea analysisArea = new JTextArea("Analysis details here");
        detailTabs.addTab("Request", requestEditor.uiComponent());
        detailTabs.addTab("Response", responseEditor.uiComponent());
        detailTabs.addTab("Analysis", new JScrollPane(analysisArea));

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
                    int modelRow = table.convertRowIndexToModel(selectedRow);
                    if (modelRow < requestResponses.size()) {
                        HttpRequestResponse requestResponse = requestResponses.get(modelRow);
                        requestEditor.setRequest(requestResponse.request());
                        responseEditor.setResponse(requestResponse.response());
                        analysisArea.setText((String) logTableModel.getValueAt(modelRow, 2));
                    }
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

    public void addLogEntry(String url, String checkType, String result, HttpRequestResponse requestResponse) {
        SwingUtilities.invokeLater(() -> {
            logTableModel.addRow(new Object[]{url, checkType, result});
            requestResponses.add(requestResponse);
        });
    }

    private void exportToXLSX(JTable table) {
        // 创建文件选择器
        JFileChooser fileChooser = new JFileChooser();
        String defaultFileName = "VulCheck_" + new SimpleDateFormat("yyyyMMdd").format(new Date()) + ".xlsx";
        fileChooser.setSelectedFile(new File(defaultFileName));
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(File f) {
                return f.isDirectory() || f.getName().toLowerCase().endsWith(".xlsx");
            }

            @Override
            public String getDescription() {
                return "XLSX Files (*.xlsx)";
            }
        });

        // 显示保存对话框
        int result = fileChooser.showSaveDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".xlsx")) {
            file = new File(file.getAbsolutePath() + ".xlsx");
        }

        // 创建XLSX文件
        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("VulCheck Log");

            // 设置表头样式
            CellStyle headerStyle = workbook.createCellStyle();
            org.apache.poi.ss.usermodel.Font headerFont = workbook.createFont();
            headerFont.setBold(true);
            headerStyle.setFont(headerFont);
            headerStyle.setAlignment(HorizontalAlignment.CENTER);

            // 创建表头
            Row headerRow = sheet.createRow(0);
            String[] headers = {"URL", "Checktype", "Result"};
            for (int i = 0; i < headers.length; i++) {
                Cell cell = headerRow.createCell(i);
                cell.setCellValue(headers[i]);
                cell.setCellStyle(headerStyle);
            }

            // 写入数据（考虑过滤后的显示顺序）
            for (int rowIndex = 0; rowIndex < table.getRowCount(); rowIndex++) {
                Row row = sheet.createRow(rowIndex + 1);
                int modelRow = table.convertRowIndexToModel(rowIndex);
                for (int colIndex = 0; colIndex < table.getColumnCount(); colIndex++) {
                    Object value = logTableModel.getValueAt(modelRow, colIndex);
                    row.createCell(colIndex).setCellValue(value != null ? value.toString() : "");
                }
            }

            // 自动调整列宽
            for (int i = 0; i < headers.length; i++) {
                sheet.autoSizeColumn(i);
            }

            // 保存文件
            try (FileOutputStream fileOut = new FileOutputStream(file)) {
                workbook.write(fileOut);
                JOptionPane.showMessageDialog(null, "导出成功: " + file.getAbsolutePath(), "导出", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "导出失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static class CheckBoxRenderer extends JCheckBox implements TableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            setSelected((Boolean) value);
            return this;
        }
    }
}