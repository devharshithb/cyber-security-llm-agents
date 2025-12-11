import os
import sys
from dotenv import load_dotenv

# Load the environment variables from the .env file
load_dotenv()

# Initialize the variables
WEB_SERVER_PORT = os.getenv("WEB_SERVER_PORT")
MAX_TOKENS = os.getenv("MAX_TOKENS")
MAX_TOKENS_PER_MESSAGE = os.getenv("MAX_TOKENS_PER_MESSAGE")
LLM_WORKING_FOLDER = os.getenv("LLM_WORKING_FOLDER", "llm_working_folder")

FTP_SERVER_ADDRESS = os.getenv("FTP_SERVER_ADDRESS")
FTP_SERVER_USER = os.getenv("FTP_SERVER_USER")
FTP_SERVER_PASS = os.getenv("FTP_SERVER_PASS")

CALDERA_SERVER = os.getenv("CALDERA_SERVER")
CALDERA_API_KEY = os.getenv("CALDERA_API_KEY")

# LLM Backend Configuration
LLM_BACKEND = os.getenv("LLM_BACKEND", "ollama")

# Ollama Configuration (default - free and local)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama2")

# OpenAI Configuration (optional)
OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME", "gpt-3.5-turbo")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Groq Configuration (optional - free tier available)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama3-8b-8192")

# Optionally, convert string values to the appropriate type if needed (e.g., integers)
WEB_SERVER_PORT = int(WEB_SERVER_PORT) if WEB_SERVER_PORT else 8800
MAX_TOKENS = int(MAX_TOKENS) if MAX_TOKENS else None
MAX_TOKENS_PER_MESSAGE = int(MAX_TOKENS_PER_MESSAGE) if MAX_TOKENS_PER_MESSAGE else None


def validate_required_config():
    """Validate that required configuration is present based on selected backend."""
    errors = []
    
    if LLM_BACKEND == "openai":
        if not OPENAI_API_KEY or OPENAI_API_KEY.startswith("<") or OPENAI_API_KEY == "":
            errors.append("OPENAI_API_KEY is not configured in .env file (required for openai backend)")
        if not OPENAI_MODEL_NAME or OPENAI_MODEL_NAME.startswith("<"):
            errors.append("OPENAI_MODEL_NAME is not configured in .env file (required for openai backend)")
    
    elif LLM_BACKEND == "groq":
        if not GROQ_API_KEY or GROQ_API_KEY.startswith("<") or GROQ_API_KEY == "":
            errors.append("GROQ_API_KEY is not configured in .env file (required for groq backend)")
        if not GROQ_MODEL or GROQ_MODEL.startswith("<"):
            errors.append("GROQ_MODEL is not configured in .env file (required for groq backend)")
    
    elif LLM_BACKEND == "ollama":
        # Ollama doesn't require API keys, just check that the base URL is set
        if not OLLAMA_BASE_URL:
            errors.append("OLLAMA_BASE_URL is not configured (defaults to http://localhost:11434)")
        if not OLLAMA_MODEL:
            errors.append("OLLAMA_MODEL is not configured (defaults to llama2)")
        # Note: We don't validate if Ollama is actually running here
        # That will be checked when trying to connect
    
    else:
        errors.append(f"Unknown LLM_BACKEND: {LLM_BACKEND}. Supported: ollama, openai, groq")
    
    if errors:
        print("\n" + "="*70)
        print("  CONFIGURATION ERROR")
        print("="*70)
        for error in errors:
            print(f"  ❌ {error}")
        print("\n  Please configure your .env file:")
        print("  1. Copy .env_template to .env if not done already")
        print("  2. Set LLM_BACKEND to 'ollama' (free, local) or 'openai'/'groq' (requires API key)")
        print("  3. Configure the required settings for your chosen backend")
        print("\n  For Ollama (recommended for free/local):")
        print("     - Install Ollama from https://ollama.ai")
        print("     - Run: ollama pull llama2")
        print("     - Ensure Ollama is running (ollama serve)")
        print("="*70 + "\n")
        sys.exit(1)


def validate_caldera_config():
    """Validate Caldera configuration (optional - only warn)."""
    if not CALDERA_SERVER or CALDERA_SERVER.startswith("<"):
        return False
    if not CALDERA_API_KEY or CALDERA_API_KEY.startswith("<"):
        return False
    return True
