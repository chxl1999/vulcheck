package com.vulcheck.poc;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.vulcheck.ui.ExtensionUI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SuppressWarnings("deprecation")
public class ReverseTabnabbingCheck implements ScanCheck {
    private final MontoyaApi api;
    private final ExtensionUI ui;
    private final Pattern linkPattern = Pattern.compile("<a\\s+[^>]*href=\"[^\"]+\"[^>]*>", Pattern.CASE_INSENSITIVE);

    public ReverseTabnabbingCheck(MontoyaApi api, ExtensionUI ui) {
        this.api = api;
        this.ui = ui;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        String responseBody = baseRequestResponse.response().bodyToString();

        // 检查是否在Target scope内
        if (!api.scope().isInScope(baseRequestResponse.request().url())) {
            return AuditResult.auditResult(new ArrayList<>());
        }

        // 查找所有<a>标签
        Matcher matcher = linkPattern.matcher(responseBody);
        boolean hasVulnerability = false;
        String payload1 = "";
        String payload2 = "";
        String payload3 = "";

        while (matcher.find()) {
            String link = matcher.group();
            if (link.contains("target=\"blank\"") || link.contains("target='_blank'")) {
                if (!link.contains("rel=\"noopener\"") && !link.contains("rel=\"noreferrer\"")) {
                    hasVulnerability = true;
                    payload1 = link;
                    payload2 = "无 rel=\"noopener\"";
                    payload3 = "无 rel=\"noreferrer\"";
                    break;
                }
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
                baseRequestResponse.request().url(),
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
        ui.addLogEntry(baseRequestResponse.request().url(), "Reverse Tabnabbing", result, baseRequestResponse);

        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        return AuditResult.auditResult(new ArrayList<>());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return ConsolidationAction.KEEP_NEW;
    }
}