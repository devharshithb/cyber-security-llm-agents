#!/usr/bin/env python3
"""Test script to verify the interactive mode works correctly."""

import sys
sys.path.insert(0, '/home/harsh/code/cyber-security-llm-agents')

# Mock the autogen module and dependencies
class MockLogging:
    @staticmethod
    def start(config=None):
        return "mock_session_id"
    
    @staticmethod
    def stop():
        pass

class MockAgent:
    def __init__(self, name):
        self.name = name
    
    def initiate_chats(self, tasks):
        print(f"[MOCK] Would initiate {len(tasks)} chat tasks")

class MockAutogen:
    runtime_logging = MockLogging()

sys.modules['autogen'] = MockAutogen()
sys.modules['autogen.runtime_logging'] = MockLogging()

# Mock other dependencies
class MockTextAgents:
    task_coordinator_agent = MockAgent("coordinator")
    internet_agent = MockAgent("internet")
    text_analyst_agent = MockAgent("text_analyst")
    attacker_agent = MockAgent("attacker")
    defender_agent = MockAgent("defender")
    intel_analyst_agent = MockAgent("intel_analyst")
    toolsmith_agent = MockAgent("toolsmith")
    decider_agent = MockAgent("decider")
    
    @staticmethod
    def register_tools():
        pass

class MockCodeAgents:
    cmd_exec_agent = MockAgent("cmd_exec")
    
    @staticmethod
    def register_tools():
        pass

text_agents = MockTextAgents()
code_agents = MockCodeAgents()

agents_module = type(sys)('agents')
agents_module.text_agents = text_agents
agents_module.code_agents = code_agents

sys.modules['agents'] = agents_module
sys.modules['agents.text_agents'] = text_agents
sys.modules['agents.code_agents'] = code_agents

# Mock utils
def mock_print_usage(session_id):
    print(f"[MOCK] Usage statistics for session: {session_id}")

def mock_clean_dir(path):
    print(f"[MOCK] Cleaning directory: {path}")

sys.modules['utils'] = type('utils', (), {})()
sys.modules['utils.logs'] = type('logs', (), {'print_usage_statistics': mock_print_usage})()
sys.modules['utils.shared_config'] = type('shared_config', (), {'clean_working_directory': mock_clean_dir})()

# Mock actions
class MockActions:
    scenarios = {
        'HELLO_AGENTS': ['test_action'],
        'TEST_SCENARIO': ['test_action'],
    }
    
    actions = {
        'test_action': [
            {
                'agent': 'text_analyst_agent',
                'message': 'Test message'
            }
        ]
    }

sys.modules['actions'] = type('actions', (), {})()
sys.modules['actions.agent_actions'] = MockActions()

# Now import and test the interactive mode
from run_agents import display_menu, retrieve_agent

print("="*70)
print(" Testing Interactive Mode Components")
print("="*70)

# Test 1: Display menu
print("\n\n[TEST 1] Testing display_menu()...")
scenario_list = display_menu()
print(f"\n✓ Menu displayed successfully")
print(f"✓ Total scenarios in menu: {len(scenario_list)}")

# Test 2: Retrieve agents
print("\n\n[TEST 2] Testing retrieve_agent()...")
test_agents = [
    'text_analyst_agent',
    'internet_agent',
    'attacker_agent',
    'defender_agent',
    'cmd_exec_agent'
]

for agent_name in test_agents:
    try:
        agent = retrieve_agent(agent_name)
        print(f"✓ Successfully retrieved: {agent_name}")
    except Exception as e:
        print(f"✗ Failed to retrieve {agent_name}: {e}")

# Test 3: Check for invalid agent
print("\n\n[TEST 3] Testing invalid agent handling...")
try:
    retrieve_agent('invalid_agent')
    print("✗ Should have raised ValueError for invalid agent")
except ValueError as e:
    print(f"✓ Correctly raised ValueError: {e}")

# Test 4: Check caldera agent is disabled
print("\n\n[TEST 4] Testing caldera agent is disabled...")
try:
    retrieve_agent('caldera_agent')
    print("✗ Should have raised RuntimeError for caldera agent")
except RuntimeError as e:
    print(f"✓ Correctly raised RuntimeError: {e}")

print("\n\n" + "="*70)
print(" All Tests Completed!")
print("="*70)
