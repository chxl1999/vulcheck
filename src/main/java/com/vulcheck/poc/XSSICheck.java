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
import com.vulcheck.utils.ScanUtils;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class XSSICheck implements PassiveScanCheck {
    private final MontoyaApi api;
    private final ExtensionUI ui;
    private final Set<String> scannedUrls = new HashSet<>();
    private int scannedCount = 0;
    private int scanningCount = 0;

    // Patterns for sensitive data detection
    private final Pattern apiKeyPattern = Pattern.compile("api_key=[\"']?([a-zA-Z0-9-_]{10,})[\"']?");
    private final Pattern sessionPattern = Pattern.compile("session=[\"']?([a-zA-Z0-9-_]{10,})[\"']?");
    private final Pattern emailPattern = Pattern.compile("email=[\"']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})[\"']?");

    public XSSICheck(MontoyaApi api, ExtensionUI ui) {
        this.api = api;
        this.ui = ui;
        api.logging().logToOutput("XSSICheck initialized");
    }

    @Override
    public String checkName() {
        return "XSSI Check";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        scanningCount++;
        String url = baseRequestResponse.request().url();
        api.logging().logToOutput("Processing URL for XSSI: " + url);
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        // Check if check is enabled
        if (!ui.isCheckEnabled("XSSI")) {
            api.logging().logToOutput("Skipping disabled check: XSSI");
            scanningCount--;
            return AuditResult.auditResult(new ArrayList<>());
        }

        // Check whitelist
        String domain = ScanUtils.extractDomain(url, api);
        if (ui.isDomainWhitelisted(domain)) {
            api.logging().logToOutput("Skipping whitelisted domain: " + domain);
            scanningCount--;
            return AuditResult.auditResult(new ArrayList<>());
        }

        // Skip if already scanned
        if (scannedUrls.contains(url)) {
            api.logging().logToOutput("Skipping already scanned URL: " + url);
            scanningCount--;
            return AuditResult.auditResult(new ArrayList<>());
        }

        // Filter by content type
        String contentType = baseRequestResponse.response().statedMimeType().toString().toLowerCase();
        api.logging().logToOutput("Content-Type: " + contentType);
        if (!contentType.contains("json") && !contentType.contains("javascript") && !contentType.contains("html") && !contentType.isEmpty()) {
            api.logging().logToOutput("Skipping non-relevant response: " + contentType);
            scannedCount++;
            scanningCount--;
            ui.updateStatistics("XSSI", scanningCount, scannedCount, issues.size(), timestamp);
            return AuditResult.auditResult(new ArrayList<>());
        }

        // Scan response body for sensitive data
        String responseBody = baseRequestResponse.response().bodyToString();
        List<String> findings = new ArrayList<>();
        try {
            Matcher apiMatcher = apiKeyPattern.matcher(responseBody);
            if (apiMatcher.find()) findings.add("API Key: " + apiMatcher.group(1));
            Matcher sessionMatcher = sessionPattern.matcher(responseBody);
            if (sessionMatcher.find()) findings.add("Session Token: " + sessionMatcher.group(1));
            Matcher emailMatcher = emailPattern.matcher(responseBody);
            if (emailMatcher.find()) findings.add("Email: " + emailMatcher.group(1));
        } catch (Exception e) {
            api.logging().logToOutput("Error scanning response body: " + e.getMessage());
        }

        // Check headers for XSSI risk
        boolean hasNosniff = baseRequestResponse.response().headerValue("X-Content-Type-Options") != null &&
                             baseRequestResponse.response().headerValue("X-Content-Type-Options").equalsIgnoreCase("nosniff");

        String result = "Pass";
        if (!findings.isEmpty() || !hasNosniff) {
            result = "Issues";
            String detail = (!findings.isEmpty() ? "Sensitive data found: " + String.join(", ", findings) : "") +
                            (!hasNosniff ? " Missing X-Content-Type-Options: nosniff" : "");
            issues.add(AuditIssue.auditIssue(
                "XSSI Vulnerability",
                detail + ". XSSI allows attackers to include scripts and steal data.",
                "1. Add X-Content-Type-Options: nosniff header.\n2. Avoid exposing sensitive data in scripts or JSON.",
                url,
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.CERTAIN,
                null,
                null,
                null,
                baseRequestResponse
            ));
        }

        scannedUrls.add(url);
        scannedCount++;
        scanningCount--;
        ui.addLogEntry(url, "XSSI", result, baseRequestResponse, timestamp, issues);
        ui.updateStatistics("XSSI", scanningCount, scannedCount, issues.size(), timestamp);
        api.logging().logToOutput("XSSI scan completed for URL: " + url + ", Issues: " + issues.size());

        return AuditResult.auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return ConsolidationAction.KEEP_BOTH;
    }
}