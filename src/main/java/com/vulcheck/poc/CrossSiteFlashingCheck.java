package com.vulcheck.poc;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
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

public class CrossSiteFlashingCheck implements ScanCheck {
    private final MontoyaApi api;
    private final ExtensionUI ui;
    private final Set<String> scannedUrls = new HashSet<>();
    private int scannedCount = 0;
    private int scanningCount = 0;
    private static final Pattern[] DANGEROUS_PATTERNS = {
        Pattern.compile("\\beval\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bloadMovie\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bgetURL\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bExternalInterface\\.call\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bSecurity\\.allowDomain\\s*\\(\\s*\"\\*\"\\s*\\)", Pattern.CASE_INSENSITIVE)
    };

    public CrossSiteFlashingCheck(MontoyaApi api, ExtensionUI ui) {
        this.api = api;
        this.ui = ui;
        api.logging().logToOutput("CrossSiteFlashingCheck initialized");
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return AuditResult.auditResult(new ArrayList<>()); // No active audit for passive checks
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        scanningCount++;
        String url = baseRequestResponse.request().url();
        api.logging().logToOutput("Processing URL for Cross Site Flashing: " + url);
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        // Check if check is enabled
        if (!ui.isCheckEnabled("Cross Site Flashing")) {
            api.logging().logToOutput("Skipping disabled check: Cross Site Flashing");
            scanningCount--;
            ui.addLogEntry(url, "Cross Site Flashing", "Pass", baseRequestResponse, timestamp, issues);
            ui.updateStatistics("Cross Site Flashing", scanningCount, scannedCount, issues.size(), timestamp);
            return AuditResult.auditResult(issues);
        }

        // Check whitelist
        String domain = ScanUtils.extractDomain(url, api);
        if (ui.isDomainWhitelisted(domain)) {
            api.logging().logToOutput("Skipping whitelisted domain: " + domain);
            scanningCount--;
            ui.addLogEntry(url, "Cross Site Flashing", "Pass", baseRequestResponse, timestamp, issues);
            ui.updateStatistics("Cross Site Flashing", scanningCount, scannedCount, issues.size(), timestamp);
            return AuditResult.auditResult(issues);
        }

        // Skip if already scanned
        if (scannedUrls.contains(url)) {
            api.logging().logToOutput("Skipping already scanned URL: " + url);
            scanningCount--;
            ui.addLogEntry(url, "Cross Site Flashing", "Pass", baseRequestResponse, timestamp, issues);
            ui.updateStatistics("Cross Site Flashing", scanningCount, scannedCount, issues.size(), timestamp);
            return AuditResult.auditResult(issues);
        }

        // Check if response is SWF
        String contentType = baseRequestResponse.response().statedMimeType().toString().toLowerCase();
        api.logging().logToOutput("Content-Type: " + contentType);
        String result = "Pass";
        if (!contentType.contains("shockwave-flash") && !url.toLowerCase().endsWith(".swf")) {
            api.logging().logToOutput("Non-SWF response: " + contentType);
            scannedCount++;
            scanningCount--;
            ui.addLogEntry(url, "Cross Site Flashing", result, baseRequestResponse, timestamp, issues);
            ui.updateStatistics("Cross Site Flashing", scanningCount, scannedCount, issues.size(), timestamp);
            return AuditResult.auditResult(issues);
        }

        try {
            // Check SWF file size
            byte[] responseBody = baseRequestResponse.response().body().getBytes();
            if (responseBody.length > 10 * 1024 * 1024) {
                api.logging().logToOutput("Skipping large SWF file: " + url);
                scannedCount++;
                scanningCount--;
                ui.addLogEntry(url, "Cross Site Flashing", result, baseRequestResponse, timestamp, issues);
                ui.updateStatistics("Cross Site Flashing", scanningCount, scannedCount, issues.size(), timestamp);
                return AuditResult.auditResult(issues);
            }

            // Convert SWF bytes to string for pattern matching
            String swfContent = new String(responseBody, "ISO-8859-1"); // Use ISO-8859-1 to preserve binary data
            api.logging().logToOutput("SWF content length: " + swfContent.length());

            // Analyze dangerous patterns
            for (Pattern pattern : DANGEROUS_PATTERNS) {
                Matcher matcher = pattern.matcher(swfContent);
                while (matcher.find()) {
                    String matchedPattern = matcher.group();
                    result = "Issues";
                    AuditIssue issue = AuditIssue.auditIssue(
                        "Cross Site Flashing: Dangerous ActionScript Pattern",
                        "Detected potentially dangerous ActionScript pattern: " + matchedPattern + " in SWF file.",
                        "1. Remove or sanitize calls to " + matchedPattern + ".\n" +
                        "2. Ensure SWF files do not allow unsafe cross-domain access.\n" +
                        "3. Validate and restrict external resource loading.",
                        url,
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.TENTATIVE, // Lower confidence due to string-based matching
                        "Cross Site Flashing vulnerabilities may allow attackers to execute malicious code or perform unauthorized actions.",
                        null,
                        null,
                        baseRequestResponse
                    );
                    issues.add(issue);
                    api.logging().logToOutput("Cross Site Flashing vulnerability found: " + matchedPattern + " at " + url);
                }
            }

            scannedUrls.add(url);
            scannedCount++;
            scanningCount--;
            ui.addLogEntry(url, "Cross Site Flashing", result, baseRequestResponse, timestamp, issues);
            ui.updateStatistics("Cross Site Flashing", scanningCount, scannedCount, issues.size(), timestamp);
            api.logging().logToOutput("Cross Site Flashing scan completed for URL: " + url + ", Issues: " + issues.size());

        } catch (Exception e) {
            api.logging().logToError("Cross Site Flashing check failed for " + url + ": " + e.getMessage());
            result = "Pass";
            ui.addLogEntry(url, "Cross Site Flashing", result, baseRequestResponse, timestamp, issues);
            scannedCount++;
            scanningCount--;
            ui.updateStatistics("Cross Site Flashing", scanningCount, scannedCount, issues.size(), timestamp);
        }

        return AuditResult.auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return ConsolidationAction.KEEP_BOTH;
    }
}