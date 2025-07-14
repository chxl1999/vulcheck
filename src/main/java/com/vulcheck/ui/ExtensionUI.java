package com.vulcheck.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

public class ExtensionUI {
    private final MontoyaApi api;
    private final DefaultTableModel logTableModel;
    private final DefaultTableModel statsTableModel;
    private final List<HttpRequestResponse> requestResponses;
    private final List<List<AuditIssue>> requestResponsesIssues;
    private final List<DomainEntry> whitelistDomains;
    private final Color selectedBackground = new Color(100, 50, 14);
    private final Color selectedForeground = Color.WHITE;

    // 白名单域名对象
    private static class DomainEntry {
        String domain;
        boolean includeSubdomains;

        DomainEntry(String domain, boolean includeSubdomains) {
            this.domain = domain;
            this.includeSubdomains = includeSubdomains;
        }

        @Override
        public String toString() {
            return domain + (includeSubdomains ? " (Include Subdomains)" : "");
        }
    }

    public ExtensionUI(MontoyaApi api) {
        this.api = api;
        this.logTableModel = new DefaultTableModel(new String[]{"URL", "Checktype", "Result", "Time"}, 0);
        this.statsTableModel = new DefaultTableModel(new String[]{"Enable", "Checklist", "Status", "VulResult", "Time"}, 0);
        this.requestResponses = new ArrayList<>();
        this.requestResponsesIssues = new ArrayList<>();
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

        // 添加 Reverse Tabnabbing、XSSI、Clickjacking 和 Cross Site Flashing 的行
        statsTableModel.addRow(new Object[]{false, "Reverse Tabnabbing", "0 scanning, 0 scanned", "0", ""});
        statsTableModel.addRow(new Object[]{false, "XSSI", "0 scanning, 0 scanned", "0", ""});
        statsTableModel.addRow(new Object[]{false, "Clickjacking", "0 scanning, 0 scanned", "0", ""});
        statsTableModel.addRow(new Object[]{false, "Cross Site Flashing", "0 scanning, 0 scanned", "0", ""});

        JTable table = new JTable(statsTableModel) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // 仅允许编辑 Enable 列
            }

            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                int modelRow = convertRowIndexToModel(row);
                String vulResult = (String) getModel().getValueAt(modelRow, 3);
                try {
                    if (Integer.parseInt(vulResult) > 0) {
                        c.setBackground(new Color(139, 69, 19));
                        c.setForeground(Color.WHITE);
                    } else {
                        c.setBackground(Color.WHITE);
                        c.setForeground(Color.BLACK);
                    }
                } catch (NumberFormatException e) {
                    c.setBackground(Color.WHITE);
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        };

        // 设置居中对齐
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(i == 0 ? new CheckBoxRenderer() : centerRenderer);
        }
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JCheckBox()));

        // 在 Enable 列名添加复选框
        JTableHeader header = table.getTableHeader();
        JCheckBox headerCheckBox = new JCheckBox();
        headerCheckBox.setHorizontalAlignment(SwingConstants.CENTER);
        header.getColumnModel().getColumn(0).setHeaderRenderer(new HeaderCheckBoxRenderer(headerCheckBox));
        headerCheckBox.addActionListener(e -> {
            boolean selected = headerCheckBox.isSelected();
            for (int i = 0; i < statsTableModel.getRowCount(); i++) {
                statsTableModel.setValueAt(selected, i, 0);
            }
            statsTableModel.fireTableDataChanged(); // 通知表格数据更新
            api.logging().logToOutput(selected ? "All checklists selected" : "All checklists unselected");
        });

        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private JPanel constructLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // 过滤器面板
        JPanel filterPanel = new JPanel();
        JComboBox<String> columnSelector = new JComboBox<>(new String[]{"URL", "Checktype", "Result", "Time"});
        JTextField keywordField = new JTextField(20);
        JButton filterButton = new JButton("Apply Filter");
        filterPanel.add(new JLabel("Filter by:"));
        filterPanel.add(columnSelector);
        filterPanel.add(keywordField);
        filterPanel.add(filterButton);

        // 日志表格
        JTable table = new JTable(logTableModel) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                int modelRow = convertRowIndexToModel(row);
                String result = (String) getModel().getValueAt(modelRow, 2);
                boolean isSelected = isRowSelected(row);
                if (isSelected) {
                    c.setBackground(selectedBackground);
                    c.setForeground(selectedForeground);
                } else if ("Issues".equals(result)) {
                    c.setBackground(new Color(139, 69, 19));
                    c.setForeground(Color.WHITE);
                } else {
                    c.setBackground(Color.WHITE);
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        };

        // 设置居中对齐
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(logTableModel);
        table.setRowSorter(sorter);
        table.setAutoCreateRowSorter(true);

        // 导出按钮
        JButton exportButton = new JButton("Export to XLSX");
        exportButton.addActionListener(e -> exportToXLSX(table));

        // ScanDetail 区域
        JTabbedPane detailTabs = new JTabbedPane();
        var requestEditor = api.userInterface().createHttpRequestEditor();
        var responseEditor = api.userInterface().createHttpResponseEditor();
        JTextArea analysisArea = new JTextArea("Analysis details here");
        analysisArea.setEditable(false);
        detailTabs.addTab("Request", requestEditor.uiComponent());
        detailTabs.addTab("Response", responseEditor.uiComponent());
        detailTabs.addTab("Analysis", new JScrollPane(analysisArea));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailTabs);
        splitPane.setDividerLocation(300);

        // 过滤器逻辑
        filterButton.addActionListener(e -> {
            String keyword = keywordField.getText().trim();
            int columnIndex = columnSelector.getSelectedIndex();
            try {
                if (keyword.isEmpty()) {
                    sorter.setRowFilter(null);
                    api.logging().logToOutput("Filter cleared");
                } else {
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(keyword), columnIndex));
                    api.logging().logToOutput("Applied filter: column=" + columnSelector.getSelectedItem() + ", keyword=" + keyword);
                }
            } catch (Exception ex) {
                api.logging().logToOutput("Filter error: " + ex.getMessage());
                JOptionPane.showMessageDialog(panel, "无效的过滤关键词: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
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
                        List<AuditIssue> issues = requestResponsesIssues.get(modelRow);
                        if (!issues.isEmpty()) {
                            AuditIssue issue = issues.get(0);
                            String analysisText = String.format("Name: %s\nDetail: %s\nRemediation: %s",
                                    issue.name(), issue.detail(), issue.remediation());
                            analysisArea.setText(analysisText);
                        } else {
                            analysisArea.setText("No issues found");
                        }
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
        DefaultListModel<DomainEntry> whitelistModel = new DefaultListModel<>();
        JList<DomainEntry> whitelistList = new JList<>(whitelistModel);
        JTextField domainField = new JTextField(20);
        JCheckBox includeSubdomainsCheckBox = new JCheckBox("Include Subdomains");
        JButton addButton = new JButton("Add to Whitelist");
        JButton removeButton = new JButton("Remove Selected");

        // Whitelist 面板
        JPanel inputPanel = new JPanel();
        inputPanel.add(new JLabel("Domain:"));
        inputPanel.add(domainField);
        inputPanel.add(includeSubdomainsCheckBox);
        inputPanel.add(addButton);
        inputPanel.add(removeButton);
        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(whitelistList), BorderLayout.CENTER);

        // 添加域名到白名单
        addButton.addActionListener(e -> {
            String domain = domainField.getText().trim();
            boolean includeSubdomains = includeSubdomainsCheckBox.isSelected();
            if (!domain.isEmpty() && !containsDomain(whitelistModel, domain)) {
                DomainEntry entry = new DomainEntry(domain, includeSubdomains);
                whitelistModel.addElement(entry);
                whitelistDomains.add(entry);
                api.logging().logToOutput("Added domain to whitelist: " + domain + ", Include Subdomains: " + includeSubdomains);
                domainField.setText("");
                includeSubdomainsCheckBox.setSelected(false);
            } else if (domain.isEmpty()) {
                api.logging().logToOutput("Failed to add domain: empty input");
                JOptionPane.showMessageDialog(panel, "请输入有效的域名", "错误", JOptionPane.ERROR_MESSAGE);
            } else {
                api.logging().logToOutput("Failed to add domain: already in whitelist: " + domain);
                JOptionPane.showMessageDialog(panel, "域名已存在于白名单", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        // 删除选中的白名单域名
        removeButton.addActionListener(e -> {
            int selectedIndex = whitelistList.getSelectedIndex();
            if (selectedIndex != -1) {
                DomainEntry removedEntry = whitelistModel.remove(selectedIndex);
                whitelistDomains.remove(removedEntry);
                api.logging().logToOutput("Removed domain from whitelist: " + removedEntry.domain);
            } else {
                api.logging().logToOutput("Failed to remove domain: no domain selected");
                JOptionPane.showMessageDialog(panel, "请先选择一个域名", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        return panel;
    }

    private boolean containsDomain(DefaultListModel<DomainEntry> model, String domain) {
        for (int i = 0; i < model.size(); i++) {
            if (model.get(i).domain.equals(domain)) {
                return true;
            }
        }
        return false;
    }

    public void addLogEntry(String url, String checkType, String result, HttpRequestResponse requestResponse, String timestamp, List<AuditIssue> issues) {
        SwingUtilities.invokeLater(() -> {
            logTableModel.addRow(new Object[]{url, checkType, result, timestamp});
            requestResponses.add(requestResponse);
            requestResponsesIssues.add(issues);
            logTableModel.fireTableDataChanged(); // 通知表格数据更新
            api.logging().logToOutput("Added log entry: URL=" + url + ", Checktype=" + checkType + ", Result=" + result + ", Time=" + timestamp);
        });
    }

    public void updateStatistics(String checkType, int scanningCount, int scannedCount, int vulCount, String timestamp) {
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < statsTableModel.getRowCount(); i++) {
                if (statsTableModel.getValueAt(i, 1).equals(checkType)) {
                    statsTableModel.setValueAt(scanningCount + " scanning, " + scannedCount + " scanned", i, 2);
                    statsTableModel.setValueAt(String.valueOf(vulCount), i, 3);
                    statsTableModel.setValueAt(timestamp, i, 4);
                    statsTableModel.fireTableDataChanged(); // 通知表格数据更新
                    api.logging().logToOutput("Updated statistics: Checktype=" + checkType + ", Status=" + scanningCount + " scanning, " + scannedCount + " scanned, VulResult=" + vulCount + ", Time=" + timestamp);
                    break;
                }
            }
        });
    }

    public boolean isDomainWhitelisted(String domain) {
        for (DomainEntry entry : whitelistDomains) {
            if (entry.includeSubdomains) {
                if (domain.equals(entry.domain) || domain.endsWith("." + entry.domain)) {
                    api.logging().logToOutput("Domain whitelisted (include subdomains): " + domain + " matches " + entry.domain);
                    return true;
                }
            } else if (domain.equals(entry.domain)) {
                api.logging().logToOutput("Domain whitelisted: " + domain);
                return true;
            }
        }
        api.logging().logToOutput("Domain not whitelisted: " + domain);
        return false;
    }

    public boolean isCheckEnabled(String checkType) {
        for (int i = 0; i < statsTableModel.getRowCount(); i++) {
            if (statsTableModel.getValueAt(i, 1).equals(checkType)) {
                boolean enabled = (Boolean) statsTableModel.getValueAt(i, 0);
                api.logging().logToOutput("Checking enable status for: " + checkType + ", Enabled: " + enabled);
                return enabled;
            }
        }
        return false;
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
            String[] headers = {"URL", "Checktype", "Result", "Time"};
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
            setHorizontalAlignment(SwingConstants.CENTER);
            if (isSelected || (Boolean) value) {
                setBackground(Color.BLUE);
                setForeground(Color.WHITE);
            } else {
                setBackground(Color.WHITE);
                setForeground(Color.BLACK);
            }
            return this;
        }
    }

    private static class HeaderCheckBoxRenderer implements TableCellRenderer {
        private final JCheckBox checkBox;

        public HeaderCheckBoxRenderer(JCheckBox checkBox) {
            this.checkBox = checkBox;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            return checkBox;
        }
    }
}