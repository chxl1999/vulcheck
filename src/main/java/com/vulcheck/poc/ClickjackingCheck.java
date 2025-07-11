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

public class ClickjackingCheck implements PassiveScanCheck {
    private final MontoyaApi api;
    private final ExtensionUI ui;
    private final Set<String> scannedUrls = new HashSet<>();
    private int scannedCount = 0;
    private int scanningCount = 0;

    public ClickjackingCheck(MontoyaApi api, ExtensionUI ui) {
        this.api = api;
        this.ui = ui;
        api.logging().logToOutput("ClickjackingCheck initialized");
    }

    @Override
    public String checkName() {
        return "Clickjacking Check";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        scanningCount++;
        String url = baseRequestResponse.request().url();
        api.logging().logToOutput("Processing URL for Clickjacking: " + url);
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        // Check if check is enabled
        if (!ui.isCheckEnabled("Clickjacking")) {
            api.logging().logToOutput("Skipping disabled check: Clickjacking");
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

        // Check if response is HTML
        String contentType = baseRequestResponse.response().statedMimeType().toString().toLowerCase();
        api.logging().logToOutput("Content-Type: " + contentType);
        if (!contentType.contains("html")) {
            api.logging().logToOutput("Skipping non-HTML response: " + contentType);
            scannedCount++;
            scanningCount--;
            ui.updateStatistics("Clickjacking", scanningCount, scannedCount, issues.size(), timestamp);
            return AuditResult.auditResult(new ArrayList<>());
        }

        // Check for X-Frame-Options header
        String xFrameOptions = baseRequestResponse.response().headerValue("X-Frame-Options");
        boolean hasValidXFrameOptions = xFrameOptions != null &&
                (xFrameOptions.equalsIgnoreCase("DENY") || xFrameOptions.equalsIgnoreCase("SAMEORIGIN"));

        // Check for CSP frame-ancestors
        String cspHeader = baseRequestResponse.response().headerValue("Content-Security-Policy");
        boolean hasValidFrameAncestors = cspHeader != null && cspHeader.toLowerCase().contains("frame-ancestors");

        String result = "Pass";
        if (!hasValidXFrameOptions && !hasValidFrameAncestors) {
            result = "Issues";
            String detail = "Missing X-Frame-Options header and no valid Content-Security-Policy frame-ancestors directive. This makes the page vulnerable to Clickjacking.";
            issues.add(AuditIssue.auditIssue(
                "Clickjacking Vulnerability",
                detail,
                "1. Add X-Frame-Options: DENY or SAMEORIGIN header.\n" +
                "2. Configure Content-Security-Policy with frame-ancestors directive to restrict framing.",
                url,
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.CERTAIN,
                null,
                null,
                null,
                baseRequestResponse
            ));
            api.logging().logToOutput("Clickjacking vulnerability found: " + url);
        }

        scannedUrls.add(url);
        scannedCount++;
        scanningCount--;
        ui.addLogEntry(url, "Clickjacking", result, baseRequestResponse, timestamp, issues);
        ui.updateStatistics("Clickjacking", scanningCount, scannedCount, issues.size(), timestamp);
        api.logging().logToOutput("Clickjacking scan completed for URL: " + url + ", Issues: " + issues.size());

        return AuditResult.auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return ConsolidationAction.KEEP_BOTH;
    }
}