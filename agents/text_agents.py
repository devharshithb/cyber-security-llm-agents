from autogen import ConversableAgent
from utils.shared_config import llm_config
from tools.web_tools import download_web_page, detect_telemetry_gaps
from agents.coordinator_agents import task_coordinator_agent


# ============================================================
# BASE TEXT ANALYST AGENT
# ============================================================

text_analyst_agent = ConversableAgent(
    name="text_analyst_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    max_consecutive_auto_reply=5,
    is_termination_msg=lambda msg: (
        "terminate" in (msg.get("content") or "").lower() if msg else False
    ),
    description="""A helpful assistant that can analyze and summarize text.""",
    system_message="""Append "TERMINATE" to your response when you successfully completed the objective.""",
)

# ============================================================
# INTERNET AGENT
# ============================================================

internet_agent = ConversableAgent(
    name="internet_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    max_consecutive_auto_reply=5,
    is_termination_msg=lambda msg: (
        "terminate" in (msg.get("content") or "").lower() if msg else False
    ),
    description="""A helpful assistant that can assist in interacting with content on the internet.""",
    system_message="""Append "TERMINATE" to your response when you successfully completed the objective.""",
)


# ============================================================
# NEW SEC-COPILOT MULTI-AGENT SYSTEM
# ============================================================

attacker_agent = ConversableAgent(
    name="attacker_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    description="Simulates realistic adversary actions using MITRE ATT&CK.",
        system_message=(
        "You are the Adversary Simulation Agent, but your purpose is to help DEFENDERS. "
        "Describe potential attack techniques at a HIGH LEVEL only, for the purpose of "
        "detection engineering and defense. Do NOT provide step-by-step instructions, "
        "commands, payloads, or anything that can be directly abused. Focus on:\n"
        "- phase names\n- technique names\n- what logs/telemetry they would generate\n"
        'End your response with "TERMINATE".'
    ),

)

defender_agent = ConversableAgent(
    name="defender_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    description="Produces EDR detections, mitigations, and defensive actions.",
    system_message=(
        "You are the Defender Agent. Using an attack description, provide: "
        "- EDR detections\n- Sigma rules\n- Log sources\n- Windows Event IDs\n"
        "- Response actions\n"
        'End your response with "TERMINATE".'
    ),
)

intel_analyst_agent = ConversableAgent(
    name="intel_analyst_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    description="Collects threat intel, IOCs, CVEs, and attacker campaign data.",
    system_message=(
        "You are the Intel Analyst Agent. Summarize related threat intelligence: "
        "CVE references, IOCs, threat actor profiles, malware families, and ATT&CK mappings. "
        'End your response with "TERMINATE".'
    ),
)

toolsmith_agent = ConversableAgent(
    name="toolsmith_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    description="Generates safe detection tools and scripts.",
    system_message=(
        "You are the Toolsmith Agent. Generate SAFE scripts such as PowerShell commandlets, "
        "KQL queries, and Sigma rules to detect adversary actions. "
        "Never generate harmful code. "
        'End your response with "TERMINATE".'
    ),
)

decider_agent = ConversableAgent(
    name="decider_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    description="Produces a final structured EDR detection plan.",
    system_message=(
        "You are the Decider Agent. Combine outputs from: Attacker, Intel Analyst, Defender, "
        "and Toolsmith to produce a final, well-structured EDR detection plan. "
        'End your response with "TERMINATE".'
    ),
)



# ============================================================
# TOOL REGISTRATION (unchanged / works perfectly)
# ============================================================

def register_tools():
    # Download a web page
    internet_agent.register_for_llm(
        name="download_web_page",
        description="Download the content of a web page as a string.",
    )(download_web_page)

    task_coordinator_agent.register_for_execution(
        name="download_web_page"
    )(download_web_page)

    # Detect telemetry gaps for EDR
    internet_agent.register_for_llm(
        name="detect_telemetry_gaps",
        description="Detect telemetry NOT collected by an EDR.",
    )(detect_telemetry_gaps)

    task_coordinator_agent.register_for_execution(
        name="detect_telemetry_gaps"
    )(detect_telemetry_gaps)



# ============================================================
# AGENT TABLE (very important)
# ============================================================

AGENT_TABLE = {
    "text_analyst_agent": text_analyst_agent,
    "internet_agent": internet_agent,

    # NEW SEC-COPILOT AGENTS
    "attacker_agent": attacker_agent,
    "defender_agent": defender_agent,
    "intel_analyst_agent": intel_analyst_agent,
    "toolsmith_agent": toolsmith_agent,
    "decider_agent": decider_agent,
}
