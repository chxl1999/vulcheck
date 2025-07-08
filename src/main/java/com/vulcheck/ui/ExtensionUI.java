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
    private final DefaultTableModel statsTableModel;
    private final List<HttpRequestResponse> requestResponses;
    private final List<String> whitelistDomains;

    public ExtensionUI(MontoyaApi api) {
        this.api = api;
        this.logTableModel = new DefaultTableModel(new String[]{"URL", "Checktype", "Result"}, 0);
        this.statsTableModel = new DefaultTableModel(new String[]{"Enable", "Checklist", "Status", "VulResult"}, 0);
        this.requestResponses = new ArrayList<>();
        this.whitelistDomains = new ArrayList<>();
        api.logging().logToOutput("ExtensionUI initialized");
    }

    public void initialize() {
        JTabbedPane extensionTabs = new JTabbedPane();
        extensionTabs.addTab("Statistics", constructStatisticsPanel());
        extensionTabs.addTab("Log", constructLogPanel());
        extensionTabs.addTab("Settings", constructSettingsPanel());
        api.userInterface().registerSuiteTab("VulCheck", extensionTabs);
        api.logging().logToOutput("VulCheck tabs registered: Statistics, Log, Settings");
    }

    private JPanel constructStatisticsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        statsTableModel.addRow(new Object[]{true, "Reverse Tabnabbing", "0 scanning, 0 scanned", "0"});
        JTable table = new JTable(statsTableModel);
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
            api.logging().logToOutput("Applied filter: column=" + columnSelector.getSelectedItem() + ", keyword=" + keyword);
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
                        api.logging().logToOutput("Selected log row: " + modelRow + ", URL: " + logTableModel.getValueAt(modelRow, 0));
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

    private JPanel constructSettingsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        DefaultListModel<String> whitelistModel = new DefaultListModel<>();
        JList<String> whitelistList = new JList<>(whitelistModel);
        JTextField domainField = new JTextField(20);
        JButton addButton = new JButton("Add to Whitelist");

        // Whitelist 面板
        JPanel inputPanel = new JPanel();
        inputPanel.add(new JLabel("Domain:"));
        inputPanel.add(domainField);
        inputPanel.add(addButton);
        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(whitelistList), BorderLayout.CENTER);

        // 添加域名到白名单
        addButton.addActionListener(e -> {
            String domain = domainField.getText().trim();
            if (!domain.isEmpty() && !whitelistModel.contains(domain)) {
                whitelistModel.addElement(domain);
                whitelistDomains.add(domain);
                api.logging().logToOutput("Added domain to whitelist: " + domain);
                domainField.setText("");
            } else if (domain.isEmpty()) {
                api.logging().logToOutput("Failed to add domain: empty input");
                JOptionPane.showMessageDialog(panel, "请输入有效的域名", "错误", JOptionPane.ERROR_MESSAGE);
            } else {
                api.logging().logToOutput("Failed to add domain: already in whitelist: " + domain);
                JOptionPane.showMessageDialog(panel, "域名已存在于白名单", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        return panel;
    }

    public void addLogEntry(String url, String checkType, String result, HttpRequestResponse requestResponse) {
        SwingUtilities.invokeLater(() -> {
            logTableModel.addRow(new Object[]{url, checkType, result});
            requestResponses.add(requestResponse);
            api.logging().logToOutput("Added log entry: URL=" + url + ", Checktype=" + checkType + ", Result=" + result);
        });
    }

    public void updateStatistics(String checkType, int scanningCount, int scannedCount, int vulCount) {
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < statsTableModel.getRowCount(); i++) {
                if (statsTableModel.getValueAt(i, 1).equals(checkType)) {
                    statsTableModel.setValueAt("0 scanning, " + scannedCount + " scanned", i, 2);
                    statsTableModel.setValueAt(String.valueOf(vulCount), i, 3);
                    api.logging().logToOutput("Updated statistics: Checktype=" + checkType + ", Status=0 scanning, " + scannedCount + " scanned, VulResult=" + vulCount);
                    break;
                }
            }
        });
    }

    public boolean isDomainWhitelisted(String domain) {
        boolean isWhitelisted = whitelistDomains.contains(domain);
        api.logging().logToOutput("Checking whitelist for domain: " + domain + ", Result: " + isWhitelisted);
        return isWhitelisted;
    }

    private void exportToXLSX(JTable table) {
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

        int result = fileChooser.showSaveDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            api.logging().logToOutput("Export cancelled by user");
            return;
        }

        File file = fileChooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".xlsx")) {
            file = new File(file.getAbsolutePath() + ".xlsx");
        }

        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("VulCheck Log");
            CellStyle headerStyle = workbook.createCellStyle();
            org.apache.poi.ss.usermodel.Font headerFont = workbook.createFont();
            headerFont.setBold(true);
            headerStyle.setFont(headerFont);
            headerStyle.setAlignment(HorizontalAlignment.CENTER);

            Row headerRow = sheet.createRow(0);
            String[] headers = {"URL", "Checktype", "Result"};
            for (int i = 0; i < headers.length; i++) {
                Cell cell = headerRow.createCell(i);
                cell.setCellValue(headers[i]);
                cell.setCellStyle(headerStyle);
            }

            for (int rowIndex = 0; rowIndex < table.getRowCount(); rowIndex++) {
                Row row = sheet.createRow(rowIndex + 1);
                int modelRow = table.convertRowIndexToModel(rowIndex);
                for (int colIndex = 0; colIndex < table.getColumnCount(); colIndex++) {
                    Object value = logTableModel.getValueAt(modelRow, colIndex);
                    row.createCell(colIndex).setCellValue(value != null ? value.toString() : "");
                }
            }

            for (int i = 0; i < headers.length; i++) {
                sheet.autoSizeColumn(i);
            }

            try (FileOutputStream fileOut = new FileOutputStream(file)) {
                workbook.write(fileOut);
                api.logging().logToOutput("Export successful: " + file.getAbsolutePath());
                JOptionPane.showMessageDialog(null, "导出成功: " + file.getAbsolutePath(), "导出", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (IOException e) {
            api.logging().logToOutput("Export failed: " + e.getMessage());
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