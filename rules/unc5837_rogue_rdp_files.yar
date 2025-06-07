/*
  YARA rules for detecting .rdp files used in the UNC5837 Rogue RDP campaign.
  Based on GTI Report: https://www.virustotal.com/gui/collection/report--25-10015981
  Author: Cline (AI Agent)
*/

rule G_Hunting_RDP_File_RemoteApp_ResourceRedir_UNC5837
{
  meta:
    author = "Cline (AI Agent), Google Threat Intelligence Group"
    description = "Detects RDP config files utilizing RemoteApp and resource redirection, similar to those in UNC5837 campaign."
    reference = "https://www.virustotal.com/gui/collection/report--25-10015981"
    hash1 = "ba4d58f2c5903776fe47c92a0ec3297cc7b9c8fa16b3bf5f40b46242e7092b46"
    date = "2024-10-29"
    actor = "UNC5837"
  strings:
    $rdp_param1 = "remoteapplicationmode:i:1" wide
    $rdp_param2 = "drivestoredirect:s:" wide // Could be more specific, e.g., drivestoredirect:s:*
    $rdp_param3 = "remoteapplicationprogram:s:" wide
    $rdp_param4 = "remoteapplicationname:s:" wide
    $rdp_param_clipboard = "redirectclipboard:i:1" wide

    // Specific strings from observed sample if available and generic enough
    $specific_app_name_fragment = "AWS Secure Storage Connection Stability Test" wide

  condition:
    uint16(0) == 0x0a0d and // Check for typical text file start (CRLF)
    filesize < 20KB and
    all of ($rdp_param1, $rdp_param2, $rdp_param_clipboard) and
    1 of ($rdp_param3, $rdp_param4) and
    // Optional: look for specific app names if they are consistent across samples
    optional ($specific_app_name_fragment)
}

rule G_Hunting_RDP_File_LetsEncrypt_Signed_UNC5837
{
  meta:
    author = "Cline (AI Agent), Google Threat Intelligence Group"
    description = "Detects signed RDP configuration files that contain a base64 encoded LetsEncrypt certificate, a TTP from UNC5837."
    reference = "https://www.virustotal.com/gui/collection/report--25-10015981"
    hash1 = "ba4d58f2c5903776fe47c92a0ec3297cc7b9c8fa16b3bf5f40b46242e7092b46"
    date = "2024-10-29"
    actor = "UNC5837"
  strings:
    // Common RDP parameters to ensure it's a valid RDP file
    $rdp_header1 = "full address:s:" wide
    $rdp_header2 = "screen mode id:i:" wide

    // Signature block start
    $signature_block_start = "signature:s:AQABAAEAAAB" wide

    // Strings indicative of Let's Encrypt in the Base64 encoded certificate data
    $lets_encrypt_b64_1 = "TGV0J3MgRW5jcnlwdA==" // "Let's Encrypt" in Base64
    $lets_encrypt_b64_2 = "bGVnY3Iub3Jn"       // "lencr.org" in Base64 (part of some LE URLs)
    $lets_encrypt_common_name_prefix_b64 = "FNQSBFbmNyeXB0" // "CN=Encrypt" (part of common name)

  condition:
    uint16(0) == 0x0a0d and
    filesize < 20KB and
    all of ($rdp_header*) and
    $signature_block_start and
    1 of ($lets_encrypt_b64_1, $lets_encrypt_b64_2, $lets_encrypt_common_name_prefix_b64)
}
