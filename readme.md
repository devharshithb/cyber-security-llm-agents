# cyber-security-llm-agents

A collection of agents that use Large Language Models (LLMs) to perform tasks common in day-to-day cyber security operations.
Built on top of [AutoGen](https://microsoft.github.io/autogen/).

Released as part of our talks at RSAC2024:  
[From Chatbot to Destroyer of Endpoints: Can ChatGPT Automate EDR Bypasses?](https://www.rsaconference.com/USA/agenda/session/From%20Chatbot%20to%20Destroyer%20of%20Endpoints%20Can%20ChatGPT%20Automate%20EDR%20Bypasses)  
[The Always-On Purple Team: An Automated CI/CD for Detection Engineering](https://www.rsaconference.com/USA/agenda/session/The%20Always-On%20Purple%20Team%20An%20Automated%20CICD%20for%20Detection%20Engineering)

<figure align="center">
  <img src="documentation/videos/detect_edr.gif" alt="Detecting EDR"/>
   <figcaption style="text-align: center;"><i>Detecting the EDR running on a Windows system based on live data extracted from https://github.com/tsale/EDR-Telemetry.</i></figcaption>
</figure>

## Key Features

- **Modular Design**: Our framework is composed of individual agents and tasks that can be combined and customized to fit your specific security needs. This modular approach ensures flexibility and scalability, allowing you to adapt to the ever-evolving landscape of cyber threats.
- **Automation**: With Cyber-Security-LLM-Agents, you can automate repetitive and complex tasks, freeing up valuable time for your security team to focus on strategic analysis and decision-making.
- **Batteries Included**: We provide a comprehensive set of pre-defined workflows, agents, and tasks that are ready to use out-of-the-box. This enables you to jumpstart your cyber security automation with proven practices and techniques.
- **Flexible LLM Backends**: Support for multiple LLM providers including local (Ollama), cloud (OpenAI, Groq), allowing you to choose based on your privacy, cost, and performance requirements.

## Getting Started

> [!CAUTION]
> Running LLM-generated source code and commands poses a security risk to your host environment! Be careful and only run this in a virtual or test environment.

### Step 1 - Install Requirements

```bash
pip install -r requirements.txt
```

### Step 2 - Configure LLM Backend

The framework supports three LLM backends:

#### Option A: Ollama (Recommended - Free & Local)

**No API keys required!** Runs completely on your machine.

1. Install Ollama from [https://ollama.ai](https://ollama.ai)

2. Pull a model (we recommend llama2 or mistral):
```bash
ollama pull llama2
# or
ollama pull mistral
```

3. Ensure Ollama is running:
```bash
ollama serve
```

4. Create your `.env` file:
```bash
cp .env_template .env
```

The default configuration in `.env_template` is already set for Ollama, so no changes needed!

```bash
LLM_BACKEND=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama2
```

#### Option B: Groq (Free Tier with API Key)

Groq offers fast inference with a generous free tier.

1. Get a free API key from [https://console.groq.com](https://console.groq.com)

2. Create your `.env` file:
```bash
cp .env_template .env
```

3. Edit `.env` and configure:
```bash
LLM_BACKEND=groq
GROQ_API_KEY=your-groq-api-key-here
GROQ_MODEL=llama3-8b-8192
```

#### Option C: OpenAI (Requires Paid API Key)

1. Get an API key from [https://platform.openai.com](https://platform.openai.com)

2. Create your `.env` file:
```bash
cp .env_template .env
```

3. Edit `.env` and configure:
```bash
LLM_BACKEND=openai
OPENAI_API_KEY=sk-your-actual-api-key-here
OPENAI_MODEL_NAME=gpt-3.5-turbo
```

### Step 3 - Run the Agents

#### Interactive Mode (Recommended)

Simply run without arguments to get an interactive menu:

```bash
python run_agents.py
```

This will display a categorized menu of all available scenarios that you can choose from.

#### Command Line Mode

Run a specific scenario directly:

```bash
python run_agents.py HELLO_AGENTS
```

Available scenarios include:
- `HELLO_AGENTS` - Simple test scenario
- `SUMMARIZE_RECENT_CISA_VULNS` - Fetch and summarize CISA KEV vulnerabilities
- `EDR_DETECTION_CHAIN` - Full 5-agent EDR detection workflow
- `RANSOMWARE_CHAIN` - Ransomware detection analysis
- And many more (see interactive menu)


### Step 4 - Start HTTP and FTP Server (Optional)

Only required if you want to host a simple HTTP and FTP server to interact with using your agents.
This is useful for demos, where you might want to showcase exfiltration or downloading of payloads onto an implant.

```bash
python run_servers.py
```


## Quick Start Example

After setup, test with:

```bash
python run_agents.py HELLO_AGENTS
```

The output should show the agent doing its best at being funny.
If you see a joke similar to below, you are all set!

```
********************************************************************************
Starting a new chat....

********************************************************************************
task_coordinator_agent (to text_analyst_agent):

Tell me a cyber security joke

--------------------------------------------------------------------------------
text_analyst_agent (to task_coordinator_agent):

Why was the computer cold? It left its Windows open. 

TERMINATE
```

## Usage

### Interactive Mode

Run without arguments for a user-friendly menu:

```bash
python run_agents.py
```

Select scenarios by number from categorized lists including:
- Basic Tests
- Core Detection Chains
- MITRE ATT&CK Tactics
- Network Security
- Web Application Security
- Cloud Security
- Insider Threat & UEBA
- DFIR & Investigation
- Detection Engineering

### Building Custom Scenarios

All scenarios are defined in `actions/agent_actions.py`. You can use that file to modify and create new scenarios. Once a new scenario has been added to the dictionary, you can run it:

```bash
python run_agents.py <scenario-name>
```


## Features

### Multi-Agent Architecture

The framework includes specialized agents:
- **Text Analyst Agent** - Analyzes and summarizes text content
- **Internet Agent** - Fetches and processes web content
- **Command Execution Agent** - Executes shell commands
- **Attacker Agent** - Simulates attacker perspectives for threat modeling
- **Defender Agent** - Proposes defensive measures and detection rules
- **Intel Analyst Agent** - Gathers and correlates threat intelligence
- **Toolsmith Agent** - Creates security tools and scripts
- **Decider Agent** - Makes strategic decisions in multi-step workflows

### Available Scenario Categories

1. **Basic Tests** - Quick validation and simple tasks
2. **Core Detection Chains** - Full multi-agent detection workflows
3. **MITRE ATT&CK Coverage** - Scenarios mapped to ATT&CK techniques
4. **Network Security** - Network intrusion and C2 detection
5. **Web Application Security** - Web attack detection and analysis
6. **Cloud Security** - Cloud compromise and misconfiguration detection
7. **Insider Threat** - UEBA and data leak detection
8. **DFIR** - Digital forensics and incident response
9. **Detection Engineering** - Sigma rules, KQL, and playbook generation


## Development

### Jupyter Notebooks

You can launch jupyter notebooks on your network interface by choice. This allows you to run the notebooks within a VM and expose them to different system - interesting for demos!

```bash
./run_notebooks.sh ens37
```

### Static Analysis and Code Quality

We ignore E501 (line too long) as this triggers on long agent and action strings.
We ignore W503 (line break before binary operator) and we are opinionated about this being OK.

```bash
flake8 --exclude=.venv --ignore=E501,W503 .
```

## Troubleshooting

### Ollama Connection Issues

If you get connection errors with Ollama:

1. Ensure Ollama is running:
```bash
ollama serve
```

2. Verify the model is pulled:
```bash
ollama list
```

3. Test the connection:
```bash
curl http://localhost:11434/api/generate -d '{"model": "llama2", "prompt": "Hello"}'
```

### Missing Dependencies

If you get module errors:
```bash
pip install -r requirements.txt
```

### Configuration Errors

The framework will validate your configuration on startup and provide helpful error messages if something is misconfigured.

## Contributions

We welcome contributions from the community! 

If you have ideas for new agents, tasks, or improvements, please feel free to fork our repository, make your changes, and submit a pull request.

## License

Released under the GNU GENERAL PUBLIC LICENSE v3 (GPL-3).

## Disclaimer

Please note that the software contained in this repository is in its early stages of development. As such, it is considered to be an early release and may contain components that are not fully stable, potentially leading to breaking changes. Users should exercise caution when using this software. 

We are committed to improving and extending the software's capabilities over the coming months, and we welcome any feedback that can help us enhance its performance and functionality.

## Acknowledgements

We are grateful for the support received by [INNOVIRIS](https://innoviris.brussels/) and the Brussels region in funding our Research & Development activities.
