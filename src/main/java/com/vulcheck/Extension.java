package com.vulcheck;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.vulcheck.poc.ReverseTabnabbingCheck;
import com.vulcheck.poc.XSSICheck;
import com.vulcheck.ui.ExtensionUI;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("VulCheck");
        montoyaApi.logging().logToOutput("VulCheck plugin initializing...");

        // Initialize UI
        ExtensionUI ui = new ExtensionUI(montoyaApi);
        ui.initialize();
        montoyaApi.logging().logToOutput("UI initialized successfully");

        // Register passive scan checks
        ReverseTabnabbingCheck reverseTabnabbingCheck = new ReverseTabnabbingCheck(montoyaApi, ui);
        montoyaApi.scanner().registerPassiveScanCheck(reverseTabnabbingCheck, ScanCheckType.PER_REQUEST);
        montoyaApi.logging().logToOutput("Passive scan check registered for Reverse Tabnabbing");

        XSSICheck xssiCheck = new XSSICheck(montoyaApi, ui);
        montoyaApi.scanner().registerPassiveScanCheck(xssiCheck, ScanCheckType.PER_REQUEST);
        montoyaApi.logging().logToOutput("Passive scan check registered for XSSI");

        montoyaApi.logging().logToOutput("VulCheck plugin loaded successfully");
    }
}