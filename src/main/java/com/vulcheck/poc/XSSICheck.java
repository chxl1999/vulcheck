package com.vulcheck.poc;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
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

public class XSSICheck implements ScanCheck {
    private final MontoyaApi api;
    private final ExtensionUI ui;
    private final Set<String> scannedUrls = new HashSet<>();
    private int scannedCount = 0;
    private int scanningCount = 0;

    // Patterns for sensitive data detection
    private final Pattern apiKeyPattern = Pattern.compile("api_key=[\"']?([a-zA-Z0-9-_]{10,})[\"']?");
    private final Pattern sessionPattern = Pattern.compile("session=[\"']?([a-zA-Z0-9-_]{10,})[\"']?");
    private final Pattern emailPattern = Pattern.compile("email=[\"']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})[\"']?");
    private final Pattern tokenPattern = Pattern.compile("token=[\"']?([a-zA-Z0-9-_]{10,})[\"']?");
    private final Pattern passwordPattern = Pattern.compile("password=[\"']?([a-zA-Z0-9-_]{8,})[\"']?");
    private final Pattern jsonKeyPattern = Pattern.compile("\"(api_key|token|password)\":\\s*\"([^\"]+)\"");

    // Common XSSI protection patterns
    private final Pattern throwProtection = Pattern.compile("^throw\\s+'allowScriptTagRemoting is false.';", Pattern.CASE_INSENSITIVE);
    private final Pattern closeParenthesisProtection = Pattern.compile("^\\)]}'");
    private final Pattern infiniteLoopProtection = Pattern.compile("^while\\(1\\);");

    public XSSICheck(MontoyaApi api, ExtensionUI ui) {
        this.api = api;
        this.ui = ui;
        api.logging().logToOutput("XSSICheck initialized");
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
        api.logging().logToOutput("Processing URL for XSSI: " + url);
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        // Check if check is enabled
        if (!ui.isCheckEnabled("XSSI")) {
            api.logging().logToOutput("Skipping disabled check: XSSI");
            scanningCount--;
            return AuditResult.auditResult(issues);
        }

        // Check whitelist
        String domain = ScanUtils.extractDomain(url, api);
        if (ui.isDomainWhitelisted(domain)) {
            api.logging().logToOutput("Skipping whitelisted domain: " + domain);
            scanningCount--;
            return AuditResult.auditResult(issues);
        }

        // Skip if already scanned
        if (scannedUrls.contains(url)) {
            api.logging().logToOutput("Skipping already scanned URL: " + url);
            scanningCount--;
            return AuditResult.auditResult(issues);
        }

        // Check if response is a potential JS file
        String contentType = baseRequestResponse.response().statedMimeType().toString().toLowerCase();
        boolean isJSFile = contentType.contains("javascript") || url.endsWith(".js") || url.endsWith(".json");
        api.logging().logToOutput("Content-Type: " + contentType + ", Is JS file: " + isJSFile);

        // Check for XSSI protection mechanisms
        String responseBody = baseRequestResponse.response().bodyToString();
        boolean isProtected = isProtected(responseBody);
        if (isProtected) {
            api.logging().logToOutput("Response is protected against XSSI: " + url);
            scannedCount++;
            scanningCount--;
            ui.updateStatistics("XSSI", scanningCount, scannedCount, issues.size(), timestamp);
            return AuditResult.auditResult(issues);
        }

        // Scan response body for sensitive data
        List<String> findings = new ArrayList<>();
        try {
            Matcher apiMatcher = apiKeyPattern.matcher(responseBody);
            if (apiMatcher.find()) findings.add("API Key: " + apiMatcher.group(1));
            Matcher sessionMatcher = sessionPattern.matcher(responseBody);
            if (sessionMatcher.find()) findings.add("Session Token: " + sessionMatcher.group(1));
            Matcher emailMatcher = emailPattern.matcher(responseBody);
            if (emailMatcher.find()) findings.add("Email: " + emailMatcher.group(1));
            Matcher tokenMatcher = tokenPattern.matcher(responseBody);
            if (tokenMatcher.find()) findings.add("Token: " + tokenMatcher.group(1));
            Matcher passwordMatcher = passwordPattern.matcher(responseBody);
            if (passwordMatcher.find()) findings.add("Password: " + passwordMatcher.group(1));
            Matcher jsonKeyMatcher = jsonKeyPattern.matcher(responseBody);
            while (jsonKeyMatcher.find()) {
                findings.add("JSON " + jsonKeyMatcher.group(1) + ": " + jsonKeyMatcher.group(2));
            }
        } catch (Exception e) {
            api.logging().logToOutput("Error scanning response body: " + e.getMessage());
        }

        // Check headers for XSSI risk
        boolean hasNosniff = baseRequestResponse.response().headerValue("X-Content-Type-Options") != null &&
                             baseRequestResponse.response().headerValue("X-Content-Type-Options").equalsIgnoreCase("nosniff");
        String corsHeader = baseRequestResponse.response().headerValue("Access-Control-Allow-Origin");
        boolean hasWildcardCors = corsHeader != null && corsHeader.equals("*");

        // Check if response is a dynamic JS file (only if it's a JS file)
        boolean isDynamicJS = isJSFile && isDynamicJSFile(baseRequestResponse);
        if (isDynamicJS) {
            findings.add("Dynamic JS file detected");
            api.logging().logToOutput("Dynamic JS file detected for URL: " + url);
        }

        String result = "Pass";
        if (isDynamicJS && (!findings.isEmpty() || !hasNosniff || hasWildcardCors)) {
            result = "Issues";
            String detail = (!findings.isEmpty() ? "Sensitive data found: " + String.join(", ", findings) : "") +
                            (!hasNosniff ? " Missing X-Content-Type-Options: nosniff" : "") +
                            (hasWildcardCors ? " Wildcard CORS header detected: Access-Control-Allow-Origin: *" : "");
            issues.add(AuditIssue.auditIssue(
                "XSSI Vulnerability",
                detail + ". Dynamic JS files may allow attackers to include scripts and steal data.",
                "1. Add X-Content-Type-Options: nosniff header.\n" +
                "2. Avoid exposing sensitive data in scripts or JSON.\n" +
                "3. Restrict CORS headers to specific origins.",
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

    private boolean isDynamicJSFile(HttpRequestResponse baseRequestResponse) {
        if (!containsAuthenticationCharacteristics(baseRequestResponse)) {
            return false;
        }

        HttpRequestResponse unauthenticatedResponse = sendUnauthenticatedRequest(baseRequestResponse);
        if (!compareResponses(baseRequestResponse, unauthenticatedResponse)) {
            api.logging().logToOutput("Dynamic JS detected due to authentication header differences: " + baseRequestResponse.request().url());
            return true;
        }

        HttpRequestResponse firstResponse = sendRequest(baseRequestResponse);
        try {
            Thread.sleep(1000); // Wait 1 second to detect time-based changes
        } catch (InterruptedException e) {
            api.logging().logToOutput("Sleep interrupted: " + e.getMessage());
        }
        HttpRequestResponse secondResponse = sendRequest(baseRequestResponse);
        if (!compareResponses(firstResponse, secondResponse)) {
            api.logging().logToOutput("Dynamic JS detected due to response differences: " + baseRequestResponse.request().url());
            return true;
        }

        return false;
    }

    private boolean containsAuthenticationCharacteristics(HttpRequestResponse requestResponse) {
        List<HttpHeader> headers = requestResponse.request().headers();
        for (HttpHeader header : headers) {
            String headerName = header.name().toLowerCase();
            if (headerName.equals("cookie") || headerName.equals("authorization")) {
                api.logging().logToOutput("Authentication header found: " + headerName);
                return true;
            }
        }
        return false;
    }

    private HttpRequestResponse sendUnauthenticatedRequest(HttpRequestResponse baseRequestResponse) {
        HttpRequest request = baseRequestResponse.request();
        List<HttpHeader> headers = new ArrayList<>(request.headers());
        headers.removeIf(header -> {
            String headerName = header.name().toLowerCase();
            return headerName.equals("cookie") || headerName.equals("authorization");
        });
        HttpRequest newRequest = request.withUpdatedHeaders(headers);
        return api.http().sendRequest(newRequest);
    }

    private boolean isProtected(String responseBody) {
        return throwProtection.matcher(responseBody).find() ||
               closeParenthesisProtection.matcher(responseBody).find() ||
               infiniteLoopProtection.matcher(responseBody).find();
    }

    private HttpRequestResponse sendRequest(HttpRequestResponse baseRequestResponse) {
        return api.http().sendRequest(baseRequestResponse.request());
    }

    private boolean compareResponses(HttpRequestResponse response1, HttpRequestResponse response2) {
        String body1 = response1.response().bodyToString();
        String body2 = response2.response().bodyToString();
        return body1.equals(body2);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return ConsolidationAction.KEEP_BOTH;
    }
}