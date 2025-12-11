import warnings
import sys

import autogen
import autogen.runtime_logging

from agents import text_agents, code_agents  # NOTE: caldera_agents removed
from agents.text_agents import task_coordinator_agent
from utils.logs import print_usage_statistics
from utils.shared_config import clean_working_directory
import actions.agent_actions


def init_agents():
    # Disable logging User warnings - better for demos
    warnings.filterwarnings("ignore", category=UserWarning)

    # Clean working directories
    clean_working_directory("/caldera")
    clean_working_directory("/pdf")
    clean_working_directory("/code")

    # Register tools
    text_agents.register_tools()
    # caldera_agents.register_tools()  # DISABLED
    code_agents.register_tools()


def retrieve_agent(agent_name: str):
    # Caldera agent is disabled in this setup
    if agent_name == "caldera_agent":
        raise RuntimeError(
            "Caldera agent is not enabled in this setup (autogen version mismatch)."
        )

    mapping = {
        "internet_agent": text_agents.internet_agent,
        "text_analyst_agent": text_agents.text_analyst_agent,
        "cmd_exec_agent": code_agents.cmd_exec_agent,

        # NEW SEC-COPILOT AGENTS
        "attacker_agent": text_agents.attacker_agent,
        "defender_agent": text_agents.defender_agent,
        "intel_analyst_agent": text_agents.intel_analyst_agent,
        "toolsmith_agent": text_agents.toolsmith_agent,
        "decider_agent": text_agents.decider_agent,
    }

    if agent_name not in mapping:
        raise ValueError(f"Unknown agent name in actions: {agent_name}")

    return mapping[agent_name]



def run_scenario(scenario_name: str):
    init_agents()

    scenario_agents = []
    scenario_messages = []
    scenario_tasks = []

    if scenario_name in actions.agent_actions.scenarios.keys():
        scenario_action_names = actions.agent_actions.scenarios[scenario_name]

        for scenario_action_name in scenario_action_names:
            for scenario_action in actions.agent_actions.actions[scenario_action_name]:
                scenario_agents.append(scenario_action["agent"])
                scenario_messages.append(scenario_action["message"])

                scenario_task = {
                    "recipient": retrieve_agent(scenario_action["agent"]),
                    "message": scenario_action["message"],
                    "silent": False,
                }

                if "clear_history" in scenario_action:
                    scenario_task["clear_history"] = scenario_action["clear_history"]
                else:
                    scenario_task["clear_history"] = True

                if "summary_prompt" in scenario_action:
                    scenario_task["summary_prompt"] = scenario_action["summary_prompt"]

                if "summary_method" in scenario_action:
                    scenario_task["summary_method"] = scenario_action["summary_method"]

                if "carryover" in scenario_action:
                    scenario_task["carryover"] = scenario_action["carryover"]

                scenario_tasks.append(scenario_task)

    if scenario_messages:
        logging_session_id = autogen.runtime_logging.start(
            config={"dbname": "logs.db"}
        )
        task_coordinator_agent.initiate_chats(scenario_tasks)
        autogen.runtime_logging.stop()
        print_usage_statistics(logging_session_id)
    else:
        print("Scenario not found, exiting")


def display_menu():
    """Display an interactive menu for selecting scenarios."""
    print("\n" + "="*70)
    print(" CYBER SECURITY LLM AGENTS - Interactive Menu")
    print("="*70)
    
    # Group scenarios by category
    categories = {
        "Basic Tests": [
            "HELLO_AGENTS",
            "SUMMARIZE_RECENT_CISA_VULNS",
            "IDENTIFY_EDR_BYPASS_TECHNIQUES",
            "TTP_REPORT_TO_TECHNIQUES",
        ],
        "Core Detection Chains": [
            "EDR_DETECTION_CHAIN",
            "RANSOMWARE_CHAIN",
            "WEBAPP_ATTACK_CHAIN",
            "CLOUD_COMPROMISE_CHAIN",
            "INSIDER_THREAT_CHAIN",
        ],
        "MITRE ATT&CK Tactics": [
            "INITIAL_ACCESS_CHAIN",
            "MALWARE_EXECUTION_CHAIN",
            "CREDENTIAL_DUMPING_CHAIN",
            "LATERAL_MOVEMENT_CHAIN",
            "PRIVILEGE_ESCALATION_CHAIN",
            "DEFENSE_EVASION_CHAIN",
            "EXFILTRATION_CHAIN",
            "LOLBINS_CHAIN",
        ],
        "Network Security": [
            "NETWORK_INTRUSION_CHAIN",
            "PORT_SCAN_DETECTION",
            "DNS_TUNNELING_DETECTION",
            "C2_CHAIN",
            "SMB_ATTACK_CHAIN",
            "RDP_BRUTEFORCE_CHAIN",
        ],
        "Web Application Security": [
            "SQL_INJECTION_CHAIN",
            "XSS_ATTACK_CHAIN",
            "SSRF_ATTACK_CHAIN",
            "AUTH_BYPASS_CHAIN",
            "API_ABUSE_CHAIN",
        ],
        "Cloud Security": [
            "AWS_IAM_ABUSE_CHAIN",
            "S3_PUBLIC_BUCKET_DETECTION",
            "AZURE_PRIVESC_CHAIN",
            "GCP_SERVICE_ACCOUNT_ABUSE",
            "CLOUD_CREDENTIAL_LEAK_CHAIN",
            "K8S_COMPROMISE_CHAIN",
        ],
        "Insider Threat & UEBA": [
            "UEBA_ANOMALY_DETECTION",
            "DATA_LEAK_DETECTION",
            "ACCOUNT_MISUSE_CHAIN",
        ],
        "DFIR & Investigation": [
            "MALWARE_FAMILY_PROFILING",
            "IOC_ENRICHMENT_CHAIN",
            "MEMORY_ANALYSIS_GUIDE",
            "WINDOWS_EVENT_INVESTIGATION",
            "NETWORK_PCAP_INVESTIGATION",
        ],
        "Detection Engineering": [
            "SIGMA_RULE_GENERATOR",
            "KQL_DETECTION_GENERATOR",
            "SIEM_USE_CASE_BUILDER",
            "PLAYBOOK_AUTOMATION",
            "INCIDENT_SUMMARY_GENERATOR",
        ],
    }
    
    scenario_list = []
    idx = 1
    
    for category, scenarios in categories.items():
        print(f"\n{category}:")
        print("-" * 70)
        for scenario in scenarios:
            print(f"  [{idx}] {scenario}")
            scenario_list.append(scenario)
            idx += 1
    
    print("\n" + "="*70)
    print("  [0] Exit")
    print("="*70)
    
    return scenario_list


def interactive_mode():
    """Run in interactive mode with menu selection."""
    while True:
        scenario_list = display_menu()
        
        try:
            choice = input("\nEnter your choice (0 to exit): ").strip()
            
            if choice == "0":
                print("\nExiting. Goodbye!")
                break
            
            choice_idx = int(choice) - 1
            
            if 0 <= choice_idx < len(scenario_list):
                scenario_name = scenario_list[choice_idx]
                print(f"\n{'='*70}")
                print(f" Running scenario: {scenario_name}")
                print(f"{'='*70}\n")
                run_scenario(scenario_name)
                
                input("\nPress Enter to continue...")
            else:
                print("\n[ERROR] Invalid choice. Please try again.")
                
        except ValueError:
            print("\n[ERROR] Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Exiting...")
            break
        except Exception as e:
            print(f"\n[ERROR] An error occurred: {e}")
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    # Check if a scenario is provided as command line argument
    if len(sys.argv) >= 2:
        scenario_to_run = sys.argv[1]
        print(f"\n{'='*70}")
        print(f" Running scenario: {scenario_to_run}")
        print(f"{'='*70}\n")
        run_scenario(scenario_to_run)
    else:
        # Run in interactive mode
        print("\n[INFO] No scenario provided. Starting interactive mode...")
        interactive_mode()
