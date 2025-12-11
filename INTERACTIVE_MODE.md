# Interactive Mode - User Guide

## Overview

The `run_agents.py` script now supports both **command-line** and **interactive menu-driven** modes, making it easier to explore and run cybersecurity scenarios without memorizing scenario names.

## Usage

### Interactive Mode (New!)

Simply run the script without any arguments to enter interactive mode:

```bash
python run_agents.py
```

or with the virtual environment:

```bash
.venv/Scripts/python.exe run_agents.py
```

You'll see a categorized menu of all available scenarios:

```
======================================================================
 CYBER SECURITY LLM AGENTS - Interactive Menu
======================================================================

Basic Tests:
----------------------------------------------------------------------
  [1] HELLO_AGENTS
  [2] SUMMARIZE_RECENT_CISA_VULNS
  [3] IDENTIFY_EDR_BYPASS_TECHNIQUES
  [4] TTP_REPORT_TO_TECHNIQUES

Core Detection Chains:
----------------------------------------------------------------------
  [5] EDR_DETECTION_CHAIN
  [6] RANSOMWARE_CHAIN
  ...and more

======================================================================
  [0] Exit
======================================================================

Enter your choice (0 to exit):
```

### Command-Line Mode (Original)

Run a specific scenario by passing its name as an argument:

```bash
python run_agents.py HELLO_AGENTS
python run_agents.py EDR_DETECTION_CHAIN
python run_agents.py RANSOMWARE_CHAIN
```

## Features

### User-Friendly Navigation

- **Categorized Scenarios**: All 47 scenarios organized into 8 logical categories:

  - Basic Tests (4 scenarios)
  - Core Detection Chains (5 scenarios)
  - MITRE ATT&CK Tactics (8 scenarios)
  - Network Security (6 scenarios)
  - Web Application Security (5 scenarios)
  - Cloud Security (6 scenarios)
  - Insider Threat & UEBA (3 scenarios)
  - DFIR & Investigation (5 scenarios)
  - Detection Engineering (5 scenarios)

- **Numbered Selection**: Simply enter a number to run a scenario

- **Graceful Exit**: Enter `0` or press `Ctrl+C` to exit

- **Repeat Execution**: After each scenario completes, press Enter to return to the menu

### Error Handling

The interactive mode includes robust error handling:

- **Invalid Input**: Prompts you to enter a valid number if you make a mistake
- **Out of Range**: Alerts you if the number is outside the valid range
- **Keyboard Interrupt**: Gracefully handles `Ctrl+C` interruptions
- **Exception Handling**: Catches and displays any runtime errors, allowing you to continue

### Continuous Operation

After running a scenario, you can:

1. View the results
2. Press Enter to return to the menu
3. Select another scenario or exit

This allows you to run multiple scenarios in a single session without restarting the script.

## Implementation Details

### Code Changes in `run_agents.py`

1. **`display_menu()` function**: Displays categorized scenarios and returns a list of scenario names

2. **`interactive_mode()` function**: Main loop that:

   - Displays the menu
   - Captures user input
   - Validates the selection
   - Runs the selected scenario
   - Handles errors gracefully
   - Returns to the menu after completion

3. **`__main__` logic**: Checks for command-line arguments:
   - If provided: runs in command-line mode (original behavior)
   - If not provided: runs in interactive mode (new behavior)

### Backward Compatibility

The original command-line interface remains fully functional. All existing scripts, documentation, and workflows that use:

```bash
python run_agents.py <SCENARIO_NAME>
```

...will continue to work exactly as before.

## Testing

All functionality has been verified:

- ✓ Menu displays all 47 scenarios correctly
- ✓ Agent retrieval works for all agent types
- ✓ Invalid agent names raise appropriate errors
- ✓ Caldera agent correctly shows as disabled
- ✓ Error handling works for invalid inputs
- ✓ Scenario validation against actual scenario definitions

## Benefits

1. **Discoverability**: New users can explore available scenarios without reading documentation
2. **Reduced Errors**: No need to remember or type scenario names
3. **Better UX**: Clear categorization helps users find relevant scenarios quickly
4. **Productivity**: Run multiple scenarios in one session
5. **Learning**: Categories provide context about what each scenario does
6. **Zero Breaking Changes**: Existing workflows remain unaffected
