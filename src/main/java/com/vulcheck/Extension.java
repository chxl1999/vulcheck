package com.vulcheck;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.vulcheck.poc.ReverseTabnabbingCheck;
import com.vulcheck.poc.XSSICheck;
import com.vulcheck.poc.ClickjackingCheck;
import com.vulcheck.poc.CrossSiteFlashingCheck;
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

        // Register scan checks
        try {
            ReverseTabnabbingCheck reverseTabnabbingCheck = new ReverseTabnabbingCheck(montoyaApi, ui);
            montoyaApi.scanner().registerScanCheck(reverseTabnabbingCheck);
            montoyaApi.logging().logToOutput("Scan check registered for Reverse Tabnabbing");

            XSSICheck xssiCheck = new XSSICheck(montoyaApi, ui);
            montoyaApi.scanner().registerScanCheck(xssiCheck);
            montoyaApi.logging().logToOutput("Scan check registered for XSSI");

            ClickjackingCheck clickjackingCheck = new ClickjackingCheck(montoyaApi, ui);
            montoyaApi.scanner().registerScanCheck(clickjackingCheck);
            montoyaApi.logging().logToOutput("Scan check registered for Clickjacking");

            CrossSiteFlashingCheck crossSiteFlashingCheck = new CrossSiteFlashingCheck(montoyaApi, ui);
            montoyaApi.scanner().registerScanCheck(crossSiteFlashingCheck);
            montoyaApi.logging().logToOutput("Scan check registered for Cross Site Flashing");

            // Pass scan checks to UI for retest functionality
            ui.setScanChecks(reverseTabnabbingCheck, xssiCheck, clickjackingCheck, crossSiteFlashingCheck);

        } catch (Exception e) {
            montoyaApi.logging().logToError("Failed to register scan checks: " + e.getMessage());
            e.printStackTrace();
        }

        montoyaApi.logging().logToOutput("VulCheck plugin loaded successfully");
    }
}