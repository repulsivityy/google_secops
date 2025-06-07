# UNC5837 Rogue RDP Campaign - Hunting Package

This package contains detection rules related to the UNC5837 Rogue RDP campaign, as detailed in the Google Threat Intelligence report: [Windows Remote Desktop Protocol Remote to Rogue](https://www.virustotal.com/gui/collection/report--25-10015981).

## Threat Overview

**Actor:** UNC5837 (Suspected Russia-nexus espionage actor)

**Campaign Summary:**
In October 2024, UNC5837 launched a novel phishing campaign targeting European government and military organizations. The campaign utilized signed `.rdp` file attachments to establish Remote Desktop Protocol (RDP) connections from victim machines. Key TTPs include:

*   **Phishing with Signed .rdp Files:** Emails contained `.rdp` files signed with Let's Encrypt certificates issued to the C2 domain, bypassing typical unsigned file warnings.
*   **RDP Resource Redirection:** Malicious `.rdp` configurations granted attackers read/write access to victim drives and clipboard content (`drivestoredirect:s:*`, `redirectclipboard:i:1`).
*   **RemoteApps:** A deceptive RemoteApp (e.g., "AWS Secure Storage Connection Stability Test") hosted on the attacker's RDP server was presented to the victim, masquerading as a local application. Victim environment variables (`%USERPROFILE%`, `%COMPUTERNAME%`, `%USERDNSDOMAIN%`) were passed as command-line arguments to this RemoteApp.
*   **Potential PyRDP Usage:** Evidence suggests the possible use of an RDP proxy tool like PyRDP to automate file exfiltration and clipboard capture.

**Primary Objectives:** Espionage and file theft.

## Detections Included

### 1. YARA-L Rules (for Google SecOps / Chronicle)

Located in: `rules/unc5837_rogue_rdp_campaign.yaral`

*   **`rdp_connection_to_unc5837_c2`**: Detects RDP client (mstsc.exe) connections to known UNC5837 C2 domains/IPs.
    *   **IOCs (Domains):** `eu-southeast-1-aws.govtr.cloud`, `eu-north-1-aws.ua-gov.cloud` (Consider moving to a reference list for scalability).
*   **`suspicious_mstsc_file_creation_unc5837`**: Detects suspicious file creation by `mstsc.exe` outside of typical temporary locations, potentially indicating abuse of RDP drive redirection for dropping malware or tools.
*   **`rdp_execution_from_outlook_temp_unc5837`**: Detects `mstsc.exe` launching `.rdp` files from Outlook temporary cache or attachment directories, a key initial access vector in this campaign.

### 2. YARA Rules (for File Scanning)

Located in: `rules/unc5837_rogue_rdp_files.yar`

*   **`G_Hunting_RDP_File_RemoteApp_ResourceRedir_UNC5837`**: Detects `.rdp` configuration files that enable RemoteApp mode and resource/drive redirection, characteristic of the campaign's malicious files.
*   **`G_Hunting_RDP_File_LetsEncrypt_Signed_UNC5837`**: Detects `.rdp` files containing a signature block and Base64 encoded strings indicative of a Let's Encrypt certificate, another TTP observed.

## IOCs

*   **SHA256 (.rdp sample):** `ba4d58f2c5903776fe47c92a0ec3297cc7b9c8fa16b3bf5f40b46242e7092b46`
*   **C2 Domain:** `eu-southeast-1-aws.govtr.cloud` (from sample `ba4d58f2...`)
*   **C2 Domain:** `eu-north-1-aws.ua-gov.cloud` (from sample `1c1941b4...`)

## Recommendations for Defenders

(Refer to the GTI report for detailed recommendations)

*   **Log Artifacts:** Monitor Windows Event Logs (TerminalServices-RDPClient/Operational: IDs 1102, 1027, 1029) and enhance logging for file creation/read events by `mstsc.exe`.
*   **System Hardening:**
    *   Block outgoing RDP to public IPs.
    *   Disable RDP resource redirection via GPO/Registry if not essential.
    *   Configure GPO to disallow `.rdp` files from unknown/untrusted publishers.
    *   Block `.rdp` file attachments at the email gateway.
*   **Hunting Queries (Conceptual - adapt to your SIEM):**
    *   Search for `mstsc.exe` process launches with command lines pointing to `.rdp` files in Outlook temp/attachment paths.
    *   Monitor for `mstsc.exe` network connections to suspicious external domains/IPs.
    *   Look for anomalous file creation events by `mstsc.exe`, especially executables or scripts written to non-standard locations.

## References

*   Google Threat Intelligence Report: [Windows Remote Desktop Protocol Remote to Rogue](https://www.virustotal.com/gui/collection/report--25-10015981)
*   CERT-UA Alert: [CERT-UA#9715](https://cert.gov.ua/article/6281076)
*   PyRDP: [https://github.com/GoSecure/pyrdp](https://github.com/GoSecure/pyrdp)
