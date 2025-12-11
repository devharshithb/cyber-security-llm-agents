#!/usr/bin/env python3
"""Verify all scenarios in the menu exist in agent_actions."""

from actions import agent_actions

# Scenarios listed in the menu
menu_scenarios = [
    # Basic Tests
    "HELLO_AGENTS",
    "SUMMARIZE_RECENT_CISA_VULNS",
    "IDENTIFY_EDR_BYPASS_TECHNIQUES",
    "TTP_REPORT_TO_TECHNIQUES",
    
    # Core Detection Chains
    "EDR_DETECTION_CHAIN",
    "RANSOMWARE_CHAIN",
    "WEBAPP_ATTACK_CHAIN",
    "CLOUD_COMPROMISE_CHAIN",
    "INSIDER_THREAT_CHAIN",
    
    # MITRE ATT&CK Tactics
    "INITIAL_ACCESS_CHAIN",
    "MALWARE_EXECUTION_CHAIN",
    "CREDENTIAL_DUMPING_CHAIN",
    "LATERAL_MOVEMENT_CHAIN",
    "PRIVILEGE_ESCALATION_CHAIN",
    "DEFENSE_EVASION_CHAIN",
    "EXFILTRATION_CHAIN",
    "LOLBINS_CHAIN",
    
    # Network Security
    "NETWORK_INTRUSION_CHAIN",
    "PORT_SCAN_DETECTION",
    "DNS_TUNNELING_DETECTION",
    "C2_CHAIN",
    "SMB_ATTACK_CHAIN",
    "RDP_BRUTEFORCE_CHAIN",
    
    # Web Application Security
    "SQL_INJECTION_CHAIN",
    "XSS_ATTACK_CHAIN",
    "SSRF_ATTACK_CHAIN",
    "AUTH_BYPASS_CHAIN",
    "API_ABUSE_CHAIN",
    
    # Cloud Security
    "AWS_IAM_ABUSE_CHAIN",
    "S3_PUBLIC_BUCKET_DETECTION",
    "AZURE_PRIVESC_CHAIN",
    "GCP_SERVICE_ACCOUNT_ABUSE",
    "CLOUD_CREDENTIAL_LEAK_CHAIN",
    "K8S_COMPROMISE_CHAIN",
    
    # Insider Threat & UEBA
    "UEBA_ANOMALY_DETECTION",
    "DATA_LEAK_DETECTION",
    "ACCOUNT_MISUSE_CHAIN",
    
    # DFIR & Investigation
    "MALWARE_FAMILY_PROFILING",
    "IOC_ENRICHMENT_CHAIN",
    "MEMORY_ANALYSIS_GUIDE",
    "WINDOWS_EVENT_INVESTIGATION",
    "NETWORK_PCAP_INVESTIGATION",
    
    # Detection Engineering
    "SIGMA_RULE_GENERATOR",
    "KQL_DETECTION_GENERATOR",
    "SIEM_USE_CASE_BUILDER",
    "PLAYBOOK_AUTOMATION",
    "INCIDENT_SUMMARY_GENERATOR",
]

# Get actual scenarios from agent_actions
actual_scenarios = set(agent_actions.scenarios.keys())
menu_scenarios_set = set(menu_scenarios)

print("="*70)
print(" Scenario Verification Report")
print("="*70)

print(f"\nTotal scenarios in menu: {len(menu_scenarios)}")
print(f"Total scenarios in agent_actions: {len(actual_scenarios)}")

# Check for scenarios in menu that don't exist
missing = menu_scenarios_set - actual_scenarios
if missing:
    print(f"\n❌ MISSING: {len(missing)} scenarios in menu don't exist:")
    for s in sorted(missing):
        print(f"   - {s}")
else:
    print(f"\n✓ All {len(menu_scenarios)} menu scenarios exist in agent_actions")

# Check for scenarios not in menu
not_in_menu = actual_scenarios - menu_scenarios_set
if not_in_menu:
    print(f"\n⚠️  WARNING: {len(not_in_menu)} scenarios exist but not in menu:")
    for s in sorted(not_in_menu):
        print(f"   - {s}")
else:
    print(f"\n✓ All agent_actions scenarios are in the menu")

# Summary
print("\n" + "="*70)
if not missing and not not_in_menu:
    print(" ✓ PERFECT MATCH - All scenarios verified!")
elif not missing:
    print(" ✓ VALID - All menu scenarios exist (but some scenarios not in menu)")
else:
    print(" ❌ ERROR - Some menu scenarios don't exist!")
print("="*70)
