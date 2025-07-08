package com.vulcheck.poc;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.vulcheck.ui.ExtensionUI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ReverseTabnabbingCheck implements PassiveScanCheck {
    private final MontoyaApi api;
    private final ExtensionUI ui;
    private final Pattern linkPattern = Pattern.compile("<a\\s+[^>]*>", Pattern.CASE_INSENSITIVE);
    private int scannedCount = 0;
    private int scanningCount = 0;

    public ReverseTabnabbingCheck(MontoyaApi api, ExtensionUI ui) {
        this.api = api;
        this.ui = ui;
        api.logging().logToOutput("ReverseTabnabbingCheck initialized");
    }

    @Override
    public String checkName() {
        return "Reverse Tabnabbing Check";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        scanningCount++;
        String url = baseRequestResponse.request().url();
        api.logging().logToOutput("Processing URL: " + url);

        // 检查是否在Whitelist中
        String domain = extractDomain(url);
        if (ui.isDomainWhitelisted(domain)) {
            api.logging().logToOutput("Skipping whitelisted domain: " + domain);
            scannedCount++;
            scanningCount--;
            ui.updateStatistics("Reverse Tabnabbing", scanningCount, scannedCount, issues.size());
            return AuditResult.auditResult(new ArrayList<>());
        }

        // 检查响应是否可能包含HTML
        String contentType = baseRequestResponse.response().statedMimeType().toString();
        api.logging().logToOutput("Content-Type: " + contentType);
        if (!contentType.toLowerCase().contains("html") && !contentType.toLowerCase().contains("text") && !contentType.isEmpty()) {
            api.logging().logToOutput("Skipping non-text response: " + contentType);
            scannedCount++;
            scanningCount--;
            ui.updateStatistics("Reverse Tabnabbing", scanningCount, scannedCount, issues.size());
            return AuditResult.auditResult(new ArrayList<>());
        }

        // 查找所有<a>标签
        String responseBody = baseRequestResponse.response().bodyToString();
        api.logging().logToOutput("Response length: " + responseBody.length());
        api.logging().logToOutput("Response snippet: " + (responseBody.length() > 100 ? responseBody.substring(0, 100) : responseBody));
        Matcher matcher = linkPattern.matcher(responseBody);
        boolean hasVulnerability = false;
        String payload1 = "";
        String payload2 = "";
        String payload3 = "";

        api.logging().logToOutput("Scanning HTML for <a> tags...");
        while (matcher.find()) {
            String link = matcher.group();
            api.logging().logToOutput("Found <a> tag: " + link);
            boolean hasTargetBlank = link.contains("target=\"blank\"") || link.contains("target='_blank'") || link.contains("target=\"_blank\"");
            boolean hasRelProtection = link.contains("rel=\"noopener\"") || link.contains("rel=\"noreferrer\"");
            api.logging().logToOutput("Target check: hasTargetBlank=" + hasTargetBlank + ", hasRelProtection=" + hasRelProtection);
            if (hasTargetBlank && !hasRelProtection) {
                hasVulnerability = true;
                payload1 = link;
                payload2 = "无 rel=\"noopener\"";
                payload3 = "无 rel=\"noreferrer\"";
                api.logging().logToOutput("Vulnerability found: " + payload1);
                break;
            } else if (hasTargetBlank) {
                api.logging().logToOutput("Safe link with rel attributes: " + link);
            }
        }

        String result;
        if (hasVulnerability) {
            result = String.format("%s, %s, %s, Reverse Tabnabbing允许新窗口通过window.opener控制原页面, 在所有target=\"_blank\"链接中添加rel=\"noopener noreferrer\"", 
                payload1, payload2, payload3);
            issues.add(AuditIssue.auditIssue(
                "Reverse Tabnabbing Vulnerability",
                "Found link with target=\"_blank\" without rel=\"noopener\" or \"noreferrer\".",
                "Add rel=\"noopener noreferrer\" to all target=\"_blank\" links.",
                url,
                AuditIssueSeverity.LOW,
                AuditIssueConfidence.CERTAIN,
                null,
                null,
                null,
                baseRequestResponse
            ));
        } else {
            result = "Pass";
        }

        // 更新UI
        scannedCount++;
        scanningCount--;
        ui.addLogEntry(url, "Reverse Tabnabbing", result, baseRequestResponse);
        ui.updateStatistics("Reverse Tabnabbing", scanningCount, scannedCount, issues.size());
        api.logging().logToOutput("Scan completed for URL: " + url + ", Issues: " + issues.size());

        return AuditResult.auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return ConsolidationAction.KEEP_BOTH;
    }

    private String extractDomain(String url) {
        try {
            String host = new java.net.URL(url).getHost();
            return host.startsWith("www.") ? host.substring(4) : host;
        } catch (Exception e) {
            api.logging().logToOutput("Error extracting domain from URL: " + url);
            return "";
        }
    }
}