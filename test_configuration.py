#!/usr/bin/env python3
"""
Configuration Test Script

This script validates that the LLM configuration is properly set up
and can be loaded without errors.
"""

import sys
import json


def test_imports():
    """Test that all required modules can be imported."""
    print("=" * 70)
    print(" Testing Module Imports")
    print("=" * 70)

    try:
        from utils import constants
        print("✓ utils.constants imported successfully")
    except Exception as e:
        print(f"✗ Failed to import utils.constants: {e}")
        return False

    try:
        from utils import shared_config
        print("✓ utils.shared_config imported successfully")
    except Exception as e:
        print(f"✗ Failed to import utils.shared_config: {e}")
        return False

    try:
        from agents import text_agents
        print("✓ agents.text_agents imported successfully")
    except Exception as e:
        print(f"✗ Failed to import agents.text_agents: {e}")
        return False

    try:
        from agents import code_agents
        print("✓ agents.code_agents imported successfully")
    except Exception as e:
        print(f"✗ Failed to import agents.code_agents: {e}")
        return False

    try:
        from actions import agent_actions
        print("✓ actions.agent_actions imported successfully")
    except Exception as e:
        print(f"✗ Failed to import actions.agent_actions: {e}")
        return False

    return True


def test_configuration():
    """Test that configuration is loaded correctly."""
    print("\n" + "=" * 70)
    print(" Testing Configuration")
    print("=" * 70)

    from utils import constants

    print(f"\nLLM Backend: {constants.LLM_BACKEND}")

    if constants.LLM_BACKEND == "ollama":
        print(f"Ollama Base URL: {constants.OLLAMA_BASE_URL}")
        print(f"Ollama Model: {constants.OLLAMA_MODEL}")
    elif constants.LLM_BACKEND == "openai":
        print(f"OpenAI Model: {constants.OPENAI_MODEL_NAME}")
        api_key_display = constants.OPENAI_API_KEY[:10] + "..." if constants.OPENAI_API_KEY and len(constants.OPENAI_API_KEY) > 10 else "NOT_SET"
        print(f"OpenAI API Key: {api_key_display}")
    elif constants.LLM_BACKEND == "groq":
        print(f"Groq Model: {constants.GROQ_MODEL}")
        api_key_display = constants.GROQ_API_KEY[:10] + "..." if constants.GROQ_API_KEY and len(constants.GROQ_API_KEY) > 10 else "NOT_SET"
        print(f"Groq API Key: {api_key_display}")

    return True


def test_llm_config():
    """Test that LLM config is generated correctly."""
    print("\n" + "=" * 70)
    print(" Testing LLM Config Generation")
    print("=" * 70)

    from utils import shared_config

    try:
        llm_config = shared_config.llm_config
        print("\n✓ LLM config generated successfully")
        print("\nConfig structure:")
        print(json.dumps(llm_config, indent=2, default=str))
        return True
    except Exception as e:
        print(f"✗ Failed to generate LLM config: {e}")
        return False


def test_validation():
    """Test configuration validation."""
    print("\n" + "=" * 70)
    print(" Testing Configuration Validation")
    print("=" * 70)

    from utils import constants

    try:
        constants.validate_required_config()
        print("\n✓ Configuration validation passed")
        return True
    except SystemExit:
        print("\n✗ Configuration validation failed")
        print("   This is expected if you haven't set up your .env file yet")
        return False


def test_agents():
    """Test that agents can be retrieved."""
    print("\n" + "=" * 70)
    print(" Testing Agent Retrieval")
    print("=" * 70)

    import run_agents

    test_agent_names = [
        "text_analyst_agent",
        "internet_agent",
        "cmd_exec_agent",
        "attacker_agent",
        "defender_agent",
        "intel_analyst_agent",
        "toolsmith_agent",
        "decider_agent",
    ]

    all_passed = True
    for agent_name in test_agent_names:
        try:
            agent = run_agents.retrieve_agent(agent_name)
            print(f"✓ Successfully retrieved: {agent_name}")
        except Exception as e:
            print(f"✗ Failed to retrieve {agent_name}: {e}")
            all_passed = False

    return all_passed


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print(" Cyber Security LLM Agents - Configuration Test Suite")
    print("=" * 70)

    results = {}

    results["imports"] = test_imports()
    results["configuration"] = test_configuration()
    results["llm_config"] = test_llm_config()
    results["validation"] = test_validation()
    results["agents"] = test_agents()

    # Summary
    print("\n" + "=" * 70)
    print(" Test Summary")
    print("=" * 70)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name:20s}: {status}")

    print("\n" + "=" * 70)
    print(f" Overall: {passed}/{total} tests passed")
    print("=" * 70)

    if passed == total:
        print("\n🎉 All tests passed! Your configuration is working correctly.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check your configuration.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
