package com.vulcheck;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.vulcheck.poc.ReverseTabnabbingCheck;
import com.vulcheck.ui.ExtensionUI;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("VulCheck");

        // 初始化UI
        ExtensionUI ui = new ExtensionUI(montoyaApi);
        ui.initialize();

        // 注册被动扫描检查
        ReverseTabnabbingCheck reverseTabnabbingCheck = new ReverseTabnabbingCheck(montoyaApi, ui);
        montoyaApi.scanner().registerScanCheck(reverseTabnabbingCheck);
    }
}