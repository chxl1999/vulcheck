package com.vulcheck.utils;

import burp.api.montoya.MontoyaApi;
import java.net.URI;

public class ScanUtils {
    public static String extractDomain(String url, MontoyaApi api) {
        try {
            String host = URI.create(url).toURL().getHost();
            return host.startsWith("www.") ? host.substring(4) : host;
        } catch (Exception e) {
            api.logging().logToOutput("Error extracting domain from URL: " + url + ", Error: " + e.getMessage());
            return "";
        }
    }
}