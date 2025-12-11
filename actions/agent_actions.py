# ============================================================
#  SAFE AGENT ACTIONS (NO CALDERA DEPENDENCIES)
#  Uses only:
#   - text_analyst_agent
#   - internet_agent
#   - cmd_exec_agent
#   - attacker_agent
#   - intel_analyst_agent
#   - defender_agent
#   - toolsmith_agent
#   - decider_agent
# ============================================================

actions = {
    # --------------------------------------------------------
    # Simple test scenario
    # --------------------------------------------------------
    "HELLO_AGENTS": [
        {"message": "Tell me a cyber security joke", "agent": "text_analyst_agent"}
    ],

    # --------------------------------------------------------
    # Summarize CISA KEV Feed
    # --------------------------------------------------------
    "SUMMARIZE_RECENT_CISA_VULNS": [
        {
            "message": """Run a single Shell command to download (using curl -sS) https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json,
            then extract the last 10 entries using jq.""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with the last 10 JSON entries dictionaries.",
            "agent": "cmd_exec_agent",
        },
        {
            "message": "Summarize the vulnerabilities. Output a table with product name, description, and reference link.",
            "summary_method": "reflection_with_llm",
            "agent": "text_analyst_agent",
        },
    ],

    # --------------------------------------------------------
    # Identify EDR bypass techniques (internet only)
    # --------------------------------------------------------
    "IDENTIFY_EDR_BYPASS_TECHNIQUES": [
        {
            "message": "Identify telemetry gaps for Elastic using https://raw.githubusercontent.com/tsale/EDR-Telemetry/main/EDR_telem.json",
            "summary_method": "last_msg",
            "carryover": "Output the list of telemetry sub-categories with a title.",
            "agent": "internet_agent",
        }
    ],

    # --------------------------------------------------------
    # MITRE ATT&CK extraction from reports
    # --------------------------------------------------------
    "TTP_REPORT_TO_TECHNIQUES": [
        {
            "message": "Download the HTML report at https://www.microsoft.com/en-us/security/blog/2024/04/22/analyzing-forest-blizzards-custom-post-compromise-tool-for-exploiting-cve-2022-38028-to-obtain-credentials/ and extract MITRE ATT&CK technique IDs.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with the extracted MITRE techniques.",
            "agent": "internet_agent",
        }
    ],

    # ========================================================
    # MAIN SEC-COPILOT MULTI-AGENT CHAINS
    # ========================================================

    # --------------------------------------------------------
    # Full 5-agent EDR detection chain
    # --------------------------------------------------------
    "EDR_DETECTION_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": (
                "For the benefit of a DEFENDER, describe at a high level how a typical "
                "attack might progress through:\n"
                "- Phishing initial access\n"
                "- Credential theft\n"
                "- Lateral movement\n"
                "- Privilege escalation\n"
                "Focus on naming techniques and what telemetry they produce, not on how to execute them."
            ),
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with the attacker chain.",
            "clear_history": True,
        },
        {
            "agent": "intel_analyst_agent",
            "message": (
                "Based on the attack chain above, gather related threat intel: "
                "CVE references, IOCs, malware families, and ATT&CK mappings."
            ),
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with threat intel summary.",
        },
        {
            "agent": "defender_agent",
            "message": (
                "Using the attack chain + intel, propose EDR detection logic, "
                "log sources, Sigma rules, Windows Event IDs, and defensive steps."
            ),
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with defender detections.",
        },
        {
            "agent": "toolsmith_agent",
            "message": (
                "Generate SAFE detection scripts: PowerShell audit commands, "
                "KQL queries, and Sigma boilerplates."
            ),
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with generated detection scripts.",
        },
        {
            "agent": "decider_agent",
            "message": "Produce the final structured EDR detection plan.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with final EDR detection plan.",
        },
    ],

    # --------------------------------------------------------
    # Ransomware incident chain
    # --------------------------------------------------------
    "RANSOMWARE_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": """Describe, at a high level, a ransomware intrusion chain including:
- Initial access (phishing/RDP abuse)
- Payload delivery
- Lateral movement
- Data staging
- Encryption
Focus on tactics, telemetry, and MITRE techniques. Do NOT provide malicious instructions.""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with the ransomware chain.",
        },
        {
            "agent": "intel_analyst_agent",
            "message": """Enrich the ransomware chain with:
- Relevant CVEs
- IOCs (hashes, domains)
- Known ransomware families
- ATT&CK mappings""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with ransomware threat intel.",
        },
        {
            "agent": "defender_agent",
            "message": """Provide ransomware detection logic:
- EDR alerts
- SIEM queries
- Sigma rules
- Windows Event IDs
- Network indicators
- Recommended mitigations""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with ransomware detection guidance.",
        },
        {
            "agent": "toolsmith_agent",
            "message": """Generate SAFE defensive scripts:
- PowerShell auditing commands
- KQL queries
- Sigma boilerplate
- Log enrichment commands""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with generated ransomware defensive scripts.",
        },
    ],

    # --------------------------------------------------------
    # Web app attack - SQLi & XSS
    # --------------------------------------------------------
    "WEBAPP_ATTACK_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": """At a high level, describe how an attacker may attempt:
- SQL injection (SQLi)
- Cross-Site Scripting (XSS)
Describe ONLY techniques and telemetry — do NOT provide exploit payloads.""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with the web app attack chain.",
        },
        {
            "agent": "intel_analyst_agent",
            "message": """Provide intel:
- Related CVEs (SQLi/XSS)
- Common web exploitation patterns
- OWASP references
- ATT&CK web techniques""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with web app threat intel.",
        },
        {
            "agent": "defender_agent",
            "message": """Provide defensive guidance:
- WAF detections
- Log analysis
- SIEM patterns
- Sigma rules for web logs
- Secure coding mitigations""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with web app detections and mitigations.",
        },
        {
            "agent": "toolsmith_agent",
            "message": """Generate SAFE detection content:
- KQL queries for web logs
- API gateway logging filters
- Sigma boilerplates for 4xx/5xx anomalies""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with generated web app detection content.",
        },
    ],

    # --------------------------------------------------------
    # Cloud compromise (AWS IAM + misconfig)
    # --------------------------------------------------------
    "CLOUD_COMPROMISE_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": """Provide a high-level AWS attack chain including:
- IAM privilege misuse
- Misconfigured S3 buckets
- Access key leakage
- Lateral movement in AWS
- Data exfiltration
Describe telemetry only (CloudTrail, GuardDuty).""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with the cloud compromise chain.",
        },
        {
            "agent": "intel_analyst_agent",
            "message": """Enrich with:
- Relevant AWS-related CVEs
- Known breaches from misconfigurations
- Cloud-specific attacker techniques
- IOCs for leaked AWS keys""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with cloud threat intel.",
        },
        {
            "agent": "defender_agent",
            "message": """Provide detections:
- CloudTrail rules
- GuardDuty findings
- IAM misconfiguration alerts
- S3 access anomaly detections
- Least privilege recommendations""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with cloud detection guidance.",
        },
        {
            "agent": "toolsmith_agent",
            "message": """Generate SAFE AWS defensive content:
- AWS CLI audit commands
- CloudTrail queries
- Scripts to detect public S3 buckets""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with generated cloud detection scripts.",
        },
    ],

    # --------------------------------------------------------
    # Insider threat scenario
    # --------------------------------------------------------
    "INSIDER_THREAT_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": """Simulate a high-level insider threat scenario:
- Abusing legitimate credentials
- Data access overuse
- Privilege misuse
- Data exfiltration attempts
Only provide behavior & telemetry, not harmful instructions.""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with insider threat chain.",
        },
        {
            "agent": "intel_analyst_agent",
            "message": """Provide intel enrichment:
- Insider threat patterns
- Common misuse cases
- Relevant ATT&CK mappings
- Historical breach examples""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with insider threat intel.",
        },
        {
            "agent": "defender_agent",
            "message": """Provide detections:
- UEBA (user behavior analytics) signals
- SIEM detections for excessive access
- Data exfiltration patterns
- Least privilege enforcement
- DLP alerts""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with insider threat detections.",
        },
        {
            "agent": "toolsmith_agent",
            "message": """Generate SAFE scripts:
- KQL for excessive file access
- PowerShell for AD privilege audits
- Sigma templates for insider anomalies""",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with insider threat detection scripts.",
        },
    ],

    # ========================================================
    # ADDITIONAL ATTACK CHAINS (shorter versions)
    # ========================================================

    "INITIAL_ACCESS_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "At a high level, describe different initial access techniques (phishing, drive-by, supply chain) and related telemetry, for defenders.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with initial access techniques and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide detection and prevention strategies for the initial access techniques described above.",
            "summary_method": "last_msg",
        },
    ],

    "MALWARE_EXECUTION_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe high-level malware execution techniques (scripts, macros, LOLBins) and the telemetry they generate.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with malware execution telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Suggest EDR/SIEM detection approaches and policies to mitigate the malware execution methods described.",
            "summary_method": "last_msg",
        },
    ],

    "CREDENTIAL_DUMPING_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe high-level credential dumping behaviors (without tools or commands) and what telemetry/logs they generate.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with credential dumping behavior summary.",
        },
        {
            "agent": "defender_agent",
            "message": "Propose detections, event IDs, and mitigations for the credential dumping behaviors described.",
            "summary_method": "last_msg",
        },
    ],

    "LATERAL_MOVEMENT_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe, for defensive purposes, common lateral movement techniques such as Pass-the-Hash, RDP misuse, WMI, and their telemetry.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with lateral movement techniques and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide detections, key logs, and recommended defensive configurations to mitigate lateral movement.",
            "summary_method": "last_msg",
        },
    ],

    "PRIVILEGE_ESCALATION_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "List common high-level privilege escalation paths on Windows or Linux, and what telemetry they create.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with privilege escalation behaviors and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Recommend detections, monitoring strategies, and controls to prevent or detect those privilege escalation behaviors.",
            "summary_method": "last_msg",
        },
    ],

    "DEFENSE_EVASION_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe at a high level how attackers may try to evade defenses (log tampering, disabling security tools) and which artifacts remain.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with defense evasion behaviors and artifacts.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide strategies to detect defense evasion and harden logging and EDR visibility.",
            "summary_method": "last_msg",
        },
    ],

    "EXFILTRATION_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe common high-level data exfiltration methods (cloud sync abuse, DNS tunneling, HTTPS exfiltration) and their telemetry.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with exfiltration techniques and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide monitoring and detection mechanisms for the exfiltration methods described.",
            "summary_method": "last_msg",
        },
    ],

    "LOLBINS_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe how living-off-the-land binaries (LOLBins) are abused, at a high level, and which logs they generate.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with LOLBins usage patterns and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Recommend detection strategies for suspicious LOLBin usage.",
            "summary_method": "last_msg",
        },
    ],

    # ========================================================
    # NETWORK ATTACK SCENARIOS
    # ========================================================

    "NETWORK_INTRUSION_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe a high-level network intrusion kill chain (reconnaissance, scanning, exploitation, persistence) and the telemetry each phase creates.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with a network intrusion chain and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide network monitoring and NIDS/NIPS rules and strategies to detect the described intrusion chain.",
            "summary_method": "last_msg",
        },
    ],

    "PORT_SCAN_DETECTION": [
        {
            "agent": "defender_agent",
            "message": "Explain how to detect internal or external port scanning activity using logs, NetFlow, IDS, and SIEM rules.",
            "summary_method": "last_msg",
        },
    ],

    "DNS_TUNNELING_DETECTION": [
        {
            "agent": "defender_agent",
            "message": "Explain how DNS tunneling looks in logs and how to detect it with SIEM queries, thresholds, and anomaly detection.",
            "summary_method": "last_msg",
        },
    ],

    "C2_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe, for defensive purposes, how command-and-control (C2) traffic is established and maintained at a high level, and what telemetry it generates.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with high-level C2 techniques and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide detection strategies for C2, including proxy logs, DNS, TLS fingerprinting, and beaconing detection.",
            "summary_method": "last_msg",
        },
    ],

    "SMB_ATTACK_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe high-level SMB abuse techniques (lateral movement, file shares misuse) and resulting telemetry.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with SMB abuse techniques and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Suggest detections via SMB logs, Windows Event IDs, and SIEM correlation rules.",
            "summary_method": "last_msg",
        },
    ],

    "RDP_BRUTEFORCE_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "At a high level, describe RDP brute-force or misuse patterns and their telemetry, for defenders.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with RDP attack patterns and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide detection tactics for RDP brute-force, including event logs, account lockout patterns, and firewall logs.",
            "summary_method": "last_msg",
        },
    ],

    # ========================================================
    # WEB APP SPECIFIC SCENARIOS
    # ========================================================

    "SQL_INJECTION_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "At a high level, explain how SQL injection attacks manifest from a defender's perspective, focusing on logs and anomalies, not payloads.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with SQLi behavioral indicators and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Describe WAF rules, input validation, and logging strategies to detect SQL injection attempts.",
            "summary_method": "last_msg",
        },
    ],

    "XSS_ATTACK_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "At a high level, describe Cross-Site Scripting (XSS) from the defender's point of view: typical patterns, telemetry, and affected logs.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with XSS behavioral patterns and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Explain how to detect and mitigate XSS using CSP, secure coding, and web application logs.",
            "summary_method": "last_msg",
        },
    ],

    "SSRF_ATTACK_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Explain, for defenders, how SSRF attacks behave and what internal and external telemetry they create.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with SSRF behaviors and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Give defensive strategies and logging patterns to detect SSRF attempts.",
            "summary_method": "last_msg",
        },
    ],

    "AUTH_BYPASS_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe high-level authentication bypass patterns from the defender viewpoint (logic flaws, weak session handling), plus telemetry.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with auth bypass patterns and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Propose monitoring and secure coding practices to detect/prevent authentication bypass.",
            "summary_method": "last_msg",
        },
    ],

    "API_ABUSE_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe, at a high level, API abuse scenarios (rate limit abuse, mass enumeration) and their observable telemetry.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with API abuse behaviors and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide detections and rate limiting/logging strategies to mitigate API abuse.",
            "summary_method": "last_msg",
        },
    ],

    # ========================================================
    # CLOUD-SPECIFIC SCENARIOS (extra)
    # ========================================================

    "AWS_IAM_ABUSE_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe high-level IAM abuse scenarios in AWS from a defender's point of view and the resulting CloudTrail/GuardDuty telemetry.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with IAM abuse techniques and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Suggest CloudTrail queries, IAM best practices, and GuardDuty findings that detect IAM abuse.",
            "summary_method": "last_msg",
        },
    ],

    "S3_PUBLIC_BUCKET_DETECTION": [
        {
            "agent": "defender_agent",
            "message": "Describe how to detect and audit public S3 buckets and misconfigurations using AWS tools and scripts.",
            "summary_method": "last_msg",
        },
    ],

    "AZURE_PRIVESC_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe, for defenders, high-level Azure privilege escalation paths and their logs/telemetry.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with Azure privilege escalation behaviors and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Explain how to detect these privilege escalation attempts using Azure AD and activity logs.",
            "summary_method": "last_msg",
        },
    ],

    "GCP_SERVICE_ACCOUNT_ABUSE": [
        {
            "agent": "attacker_agent",
            "message": "Describe how service accounts can be abused in GCP at a high level and what telemetry would be visible.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with GCP service account abuse behaviors and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Propose detections and IAM configurations to reduce service account abuse risk.",
            "summary_method": "last_msg",
        },
    ],

    "CLOUD_CREDENTIAL_LEAK_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Explain, for defenders, how leaked cloud keys might be misused and what telemetry their misuse generates.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with cloud credential leak abuse patterns and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Give detection ideas and playbook steps for handling leaked cloud credentials.",
            "summary_method": "last_msg",
        },
    ],

    "K8S_COMPROMISE_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe, at high level, Kubernetes compromise scenarios and their logs/telemetry from a defender perspective.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with K8s compromise techniques and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Outline detection and hardening strategies for Kubernetes clusters.",
            "summary_method": "last_msg",
        },
    ],

    # ========================================================
    # UEBA / INSIDER & DATA SECURITY (some already above)
    # ========================================================

    "UEBA_ANOMALY_DETECTION": [
        {
            "agent": "defender_agent",
            "message": "Explain how UEBA can detect anomalous user activity and what signals are most useful to track insider risk.",
            "summary_method": "last_msg",
        },
    ],

    "DATA_LEAK_DETECTION": [
        {
            "agent": "defender_agent",
            "message": "Describe ways to detect data leaks (DLP, anomaly in data transfers, cloud logs) and how to configure alerts.",
            "summary_method": "last_msg",
        },
    ],

    "ACCOUNT_MISUSE_CHAIN": [
        {
            "agent": "attacker_agent",
            "message": "Describe high-level account misuse patterns (privilege abuse, off-hours access) and related telemetry.",
            "summary_method": "last_msg",
            "carryover": "Replace this placeholder with account misuse behaviors and telemetry.",
        },
        {
            "agent": "defender_agent",
            "message": "Provide monitoring strategies and rules to detect account misuse.",
            "summary_method": "last_msg",
        },
    ],

    # ========================================================
    # DFIR / INVESTIGATION SCENARIOS
    # ========================================================

    "MALWARE_FAMILY_PROFILING": [
        {
            "agent": "intel_analyst_agent",
            "message": "Given a high-level description of malware behavior, explain likely malware families, their TTPs, and references.",
            "summary_method": "last_msg",
        },
    ],

    "IOC_ENRICHMENT_CHAIN": [
        {
            "agent": "intel_analyst_agent",
            "message": "Given some IOCs (IP, domain, hash), explain how to enrich them using OSINT and threat intel sources.",
            "summary_method": "last_msg",
        },
    ],

    "MEMORY_ANALYSIS_GUIDE": [
        {
            "agent": "text_analyst_agent",
            "message": "Provide a step-by-step high-level guide on memory forensics and what artifacts to look for (no tooling specifics needed).",
            "summary_method": "last_msg",
        },
    ],

    "WINDOWS_EVENT_INVESTIGATION": [
        {
            "agent": "text_analyst_agent",
            "message": "Explain how to investigate suspicious Windows events (4624, 4625, 4688, etc.) in the context of an incident.",
            "summary_method": "last_msg",
        },
    ],

    "NETWORK_PCAP_INVESTIGATION": [
        {
            "agent": "text_analyst_agent",
            "message": "Provide a high-level methodology for investigating a pcap file in a network intrusion case.",
            "summary_method": "last_msg",
        },
    ],

    # ========================================================
    # DETECTION ENGINEERING / AUTOMATION
    # ========================================================

    "SIGMA_RULE_GENERATOR": [
        {
            "agent": "toolsmith_agent",
            "message": "Given a high-level detection idea, explain how to translate it into a Sigma rule template (no real malicious content).",
            "summary_method": "last_msg",
        },
    ],

    "KQL_DETECTION_GENERATOR": [
        {
            "agent": "toolsmith_agent",
            "message": "Explain how to write KQL queries for Microsoft Sentinel to detect suspicious behaviors based on a described scenario.",
            "summary_method": "last_msg",
        },
    ],

    "SIEM_USE_CASE_BUILDER": [
        {
            "agent": "defender_agent",
            "message": "Describe how to design a SIEM use case end-to-end: data sources, correlation logic, and alerting thresholds.",
            "summary_method": "last_msg",
        },
    ],

    "PLAYBOOK_AUTOMATION": [
        {
            "agent": "defender_agent",
            "message": "Explain how to build an automated incident response playbook for a given scenario (high level, tool-agnostic).",
            "summary_method": "last_msg",
        },
    ],

    "INCIDENT_SUMMARY_GENERATOR": [
        {
            "agent": "text_analyst_agent",
            "message": "Given incident notes, summarize key details, impact, root cause, and recommendations in a structured format.",
            "summary_method": "last_msg",
        },
    ],

    # --------------------------------------------------------
    # Disabled scenarios (Caldera removed)
    # --------------------------------------------------------
    # "DETECT_EDR": [ ... ],
    # "HELLO_CALDERA": [ ... ],
    # "COLLECT_CALDERA_INFO": [ ... ],
    # "DETECT_AGENT_PRIVILEGES": [ ... ],
    # "TTP_REPORT_TO_ADVERSARY_PROFILE": [ ... ],
}


# ============================================================
#  SCENARIO GROUPING (ROUTER)
# ============================================================

scenarios = {
    "HELLO_AGENTS": ["HELLO_AGENTS"],
    "SUMMARIZE_RECENT_CISA_VULNS": ["SUMMARIZE_RECENT_CISA_VULNS"],
    "IDENTIFY_EDR_BYPASS_TECHNIQUES": ["IDENTIFY_EDR_BYPASS_TECHNIQUES"],
    "TTP_REPORT_TO_TECHNIQUES": ["TTP_REPORT_TO_TECHNIQUES"],

    "EDR_DETECTION_CHAIN": ["EDR_DETECTION_CHAIN"],
    "RANSOMWARE_CHAIN": ["RANSOMWARE_CHAIN"],
    "WEBAPP_ATTACK_CHAIN": ["WEBAPP_ATTACK_CHAIN"],
    "CLOUD_COMPROMISE_CHAIN": ["CLOUD_COMPROMISE_CHAIN"],
    "INSIDER_THREAT_CHAIN": ["INSIDER_THREAT_CHAIN"],

    "INITIAL_ACCESS_CHAIN": ["INITIAL_ACCESS_CHAIN"],
    "MALWARE_EXECUTION_CHAIN": ["MALWARE_EXECUTION_CHAIN"],
    "CREDENTIAL_DUMPING_CHAIN": ["CREDENTIAL_DUMPING_CHAIN"],
    "LATERAL_MOVEMENT_CHAIN": ["LATERAL_MOVEMENT_CHAIN"],
    "PRIVILEGE_ESCALATION_CHAIN": ["PRIVILEGE_ESCALATION_CHAIN"],
    "DEFENSE_EVASION_CHAIN": ["DEFENSE_EVASION_CHAIN"],
    "EXFILTRATION_CHAIN": ["EXFILTRATION_CHAIN"],
    "LOLBINS_CHAIN": ["LOLBINS_CHAIN"],

    "NETWORK_INTRUSION_CHAIN": ["NETWORK_INTRUSION_CHAIN"],
    "PORT_SCAN_DETECTION": ["PORT_SCAN_DETECTION"],
    "DNS_TUNNELING_DETECTION": ["DNS_TUNNELING_DETECTION"],
    "C2_CHAIN": ["C2_CHAIN"],
    "SMB_ATTACK_CHAIN": ["SMB_ATTACK_CHAIN"],
    "RDP_BRUTEFORCE_CHAIN": ["RDP_BRUTEFORCE_CHAIN"],

    "SQL_INJECTION_CHAIN": ["SQL_INJECTION_CHAIN"],
    "XSS_ATTACK_CHAIN": ["XSS_ATTACK_CHAIN"],
    "SSRF_ATTACK_CHAIN": ["SSRF_ATTACK_CHAIN"],
    "AUTH_BYPASS_CHAIN": ["AUTH_BYPASS_CHAIN"],
    "API_ABUSE_CHAIN": ["API_ABUSE_CHAIN"],

    "AWS_IAM_ABUSE_CHAIN": ["AWS_IAM_ABUSE_CHAIN"],
    "S3_PUBLIC_BUCKET_DETECTION": ["S3_PUBLIC_BUCKET_DETECTION"],
    "AZURE_PRIVESC_CHAIN": ["AZURE_PRIVESC_CHAIN"],
    "GCP_SERVICE_ACCOUNT_ABUSE": ["GCP_SERVICE_ACCOUNT_ABUSE"],
    "CLOUD_CREDENTIAL_LEAK_CHAIN": ["CLOUD_CREDENTIAL_LEAK_CHAIN"],
    "K8S_COMPROMISE_CHAIN": ["K8S_COMPROMISE_CHAIN"],

    "UEBA_ANOMALY_DETECTION": ["UEBA_ANOMALY_DETECTION"],
    "DATA_LEAK_DETECTION": ["DATA_LEAK_DETECTION"],
    "ACCOUNT_MISUSE_CHAIN": ["ACCOUNT_MISUSE_CHAIN"],

    "MALWARE_FAMILY_PROFILING": ["MALWARE_FAMILY_PROFILING"],
    "IOC_ENRICHMENT_CHAIN": ["IOC_ENRICHMENT_CHAIN"],
    "MEMORY_ANALYSIS_GUIDE": ["MEMORY_ANALYSIS_GUIDE"],
    "WINDOWS_EVENT_INVESTIGATION": ["WINDOWS_EVENT_INVESTIGATION"],
    "NETWORK_PCAP_INVESTIGATION": ["NETWORK_PCAP_INVESTIGATION"],

    "SIGMA_RULE_GENERATOR": ["SIGMA_RULE_GENERATOR"],
    "KQL_DETECTION_GENERATOR": ["KQL_DETECTION_GENERATOR"],
    "SIEM_USE_CASE_BUILDER": ["SIEM_USE_CASE_BUILDER"],
    "PLAYBOOK_AUTOMATION": ["PLAYBOOK_AUTOMATION"],
    "INCIDENT_SUMMARY_GENERATOR": ["INCIDENT_SUMMARY_GENERATOR"],
}
