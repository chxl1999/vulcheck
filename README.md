VulCheck Burp Suite Extension
Project Overview
The VulCheck extension is a Burp Suite plugin designed to detect Reverse Tabnabbing vulnerabilities in HTTP responses. It processes HTTP traffic from the Proxy's HTTP History, scanning for <a> tags with target="_blank" lacking rel="noopener" or rel="noreferrer". The plugin provides a user interface with Statistics, Log, and Settings tabs to manage scanning, view results, and configure whitelists.
Current Version

Burp Suite Version: 2025.6.1
Montoya API: 2025.6
JDK: 21
Dependencies:
org.apache.poi:poi:5.2.3
org.apache.poi:poi-ooxml:5.2.3


Artifacts:
Extension.java (artifact_id: 6d75d228, version: a492e97c)
ReverseTabnabbingCheck.java (artifact_id: 71cc79a6, version: c55c6703)
ExtensionUI.java (artifact_id: af391636, version: aed43064)
build.gradle.kts (artifact_id: a4fc5873)
Test HTML (artifact_id: 93f58971)



Features

Statistics Page:

Displays checklist (Reverse Tabnabbing), Enable status (checkbox, default off), Status (0 scanning, X scanned), VulResult (vulnerability count), and Time (last scan timestamp).
Rows with VulResult > 0 highlighted in red-brown (Color(139, 69, 19)).
Enable column uses checkboxes (blue background, white check when selected).
Enable column header has a checkbox for select-all/unselect-all.
All table text centered.


Log Page:

Columns: URL, Checktype, Result (Issues or Pass), Time.
Rows with Result="Issues" highlighted in red-brown, selected rows darker (Color(100, 50, 14)).
Filter supports case-insensitive keyword matching.
ScanDetail tabs (Request, Response, Analysis) show AuditIssue details.
All table text centered.


Settings Page:

Whitelist management: add/remove domains with optional subdomains.
Whitelisted domains (and paths) skipped, not counted in scans.
Input validation prevents empty or duplicate domains.


Scanning Logic (ReverseTabnabbingCheck.java):

Implements PassiveScanCheck to scan HTTP responses.
Checks <a> tags for target="_blank" without rel="noopener" or rel="noreferrer".
Skips scans for disabled checklists (Enable=false), whitelisted domains, or previously scanned URLs (using Set<String> scannedUrls).
Off-state skips don’t increment scannedCount.
Detailed logging in Extender > Output.



Test Setup

Test URL: http://121.4.252.202/vultest/ReverseTabnabbing.html
Contains <a href="https://example.com" target="_blank"> (vulnerable) and <a href="https://example.com" target="_blank" rel="noopener noreferrer"> (safe).


Steps:
Enable Scanner > Scan Configuration > Passive Scanning.
Access test URL via browser or Target > Site map > Crawl.
In Statistics, enable Reverse Tabnabbing checkbox.
Verify Log page shows Issues (red-brown), Statistics shows VulResult=1, Status=0 scanning, 1 scanned.



Expected Output

Extender > Output:VulCheck plugin initializing...
ExtensionUI initialized
VulCheck tabs registered: Statistics, Log, Settings
ReverseTabnabbingCheck initialized
Passive scan check registered for Reverse Tabnabbing
VulCheck plugin loaded successfully
Processing URL: http://121.4.252.202/vultest/ReverseTabnabbing.html
Checking enable status for: Reverse Tabnabbing, Enabled: true
Domain not whitelisted: 121.4.252.202
Content-Type: HTML
Response length: 608
Response snippet: <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" con
Scanning HTML for <a> tags...
Found <a> tag: <a href="https://example.com" target="_blank">
Target check: hasTargetBlank=true, hasRelProtection=false
Vulnerability found: <a href="https://example.com" target="_blank">
Added log entry: URL=http://121.4.252.202/vultest/ReverseTabnabbing.html, Checktype=Reverse Tabnabbing, Result=Issues, Time=2025-07-09 11:59:00
Updated statistics: Checktype=Reverse Tabnabbing, Status=0 scanning, 1 scanned, VulResult=1, Time=2025-07-09 11:59:00
Scan completed for URL: http://121.4.252.202/vultest/ReverseTabnabbing.html, Issues: 1



Known Issues

Removed unused imports java.awt.event.MouseAdapter and java.awt.event.MouseEvent in ExtensionUI.java to resolve warnings.
Previous issues with Enable column (On/Off text) fixed by reverting to checkboxes.

Development Notes

Ensure Scanner > Passive Scanning is enabled for scans.
Use http://121.4.252.202/vultest/ReverseTabnabbing.html for testing.
Check Extender > Errors and Proxy > HTTP history if scans fail.
Regular expression for <a> tags: <a\\s+[^>]*> (case-insensitive).
Build with ./gradlew build, load JAR in Burp Suite.

Reference Resources

Montoya API 文档 https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
Burp Suite 扩展示例 https://github.com/PortSwigger/burp-extensions-montoya-api-examples
Burp Suite 文档 https://portswigger.net/burp/documentation
