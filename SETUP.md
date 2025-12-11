# Setup Guide - Cyber Security LLM Agents

## Quick Start

This guide will help you set up and run the Cyber Security LLM Agents framework.

### Prerequisites

- Python 3.8 or higher
- pip package manager
- OpenAI API key or compatible LLM API

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Configure Environment

1. Copy the environment template:

```bash
cp .env_template .env
```

2. Edit `.env` and configure your settings:

```bash
# Required settings
OPENAI_API_KEY="your-api-key-here"
OPENAI_MODEL_NAME="gpt-3.5-turbo-0125"  # or gpt-4, etc.

# Optional settings (for HTTP/FTP servers)
WEB_SERVER_PORT=8800
FTP_SERVER_ADDRESS="192.168.1.100:2100"
FTP_SERVER_USER="user"
FTP_SERVER_PASS="12345"
```

### Step 3: Run the Agents

#### Interactive Mode (Recommended)

Simply run without arguments to get an interactive menu:

```bash
python run_agents.py
```

This will display a categorized menu of all available scenarios:

- Basic Tests
- Core Detection Chains
- MITRE ATT&CK Tactics
- Network Security
- Web Application Security
- Cloud Security
- Insider Threat & UEBA
- DFIR & Investigation
- Detection Engineering

#### Command Line Mode

Run a specific scenario directly:

```bash
python run_agents.py HELLO_AGENTS
```

### Step 4: Run HTTP/FTP Servers (Optional)

If you need to test data exfiltration or payload hosting scenarios:

```bash
python run_servers.py
```

This will start:

- HTTP server on configured port (default: 8800)
- FTP server on configured address

Press Ctrl+C to stop the servers.

## Available Scenarios

### Quick Tests

- `HELLO_AGENTS` - Simple test to verify setup
- `SUMMARIZE_RECENT_CISA_VULNS` - Summarize recent CISA vulnerabilities
- `IDENTIFY_EDR_BYPASS_TECHNIQUES` - Identify EDR telemetry gaps
- `TTP_REPORT_TO_TECHNIQUES` - Extract MITRE ATT&CK techniques from reports

### Detection Engineering

- `EDR_DETECTION_CHAIN` - Full 5-agent EDR detection workflow
- `RANSOMWARE_CHAIN` - Ransomware detection analysis
- `WEBAPP_ATTACK_CHAIN` - Web application security analysis
- `CLOUD_COMPROMISE_CHAIN` - Cloud security compromise detection
- `INSIDER_THREAT_CHAIN` - Insider threat detection

### MITRE ATT&CK Coverage

- `INITIAL_ACCESS_CHAIN` - Initial access techniques
- `MALWARE_EXECUTION_CHAIN` - Malware execution analysis
- `CREDENTIAL_DUMPING_CHAIN` - Credential dumping detection
- `LATERAL_MOVEMENT_CHAIN` - Lateral movement patterns
- `PRIVILEGE_ESCALATION_CHAIN` - Privilege escalation detection
- `DEFENSE_EVASION_CHAIN` - Defense evasion techniques
- `EXFILTRATION_CHAIN` - Data exfiltration detection
- And many more...

## Troubleshooting

### Module Not Found Errors

If you get `ModuleNotFoundError`, ensure dependencies are installed:

```bash
pip install -r requirements.txt
```

### API Key Issues

Verify your `.env` file has the correct API key:

```bash
cat .env | grep OPENAI_API_KEY
```

### Permission Errors

Ensure the `llm_working_folder` directory exists and is writable:

```bash
mkdir -p llm_working_folder/{caldera,pdf,code}
chmod 755 llm_working_folder
```

### Jupyter Notebooks

To run Jupyter notebooks on a specific network interface:

```bash
./run_notebooks.sh <interface-name>
# Example: ./run_notebooks.sh eth0
```

## Code Quality

Run static analysis:

```bash
flake8 --exclude=.venv --ignore=E501,W503 .
```

## Development

- All scenarios are defined in `actions/agent_actions.py`
- Agents are defined in `agents/` directory
- Tools are defined in `tools/` directory
- Utilities are in `utils/` directory

## Security Warning

⚠️ **CAUTION**: Running LLM-generated code and commands poses security risks. Only run this framework in isolated/test environments.

## Support

For issues, questions, or contributions, please refer to the main README.md file.
