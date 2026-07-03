"""
Configuration for CTI Agentic System
All values can be overridden with environment variables.
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
INPUT_DIR = DATA_DIR / "input"
SAMPLES_DIR = DATA_DIR / "samples"
LOGS_DIR = BASE_DIR / "logs"
STATIC_DIR = BASE_DIR / "static"

# Create directories
for dir_path in [DATA_DIR, INPUT_DIR, SAMPLES_DIR, LOGS_DIR, STATIC_DIR]:
    dir_path.mkdir(exist_ok=True, parents=True)

# Agent settings
POLLING_INTERVAL = int(os.getenv("POLLING_INTERVAL", "5"))  # seconds
MAX_EVENTS_PER_CYCLE = int(os.getenv("MAX_EVENTS_PER_CYCLE", "5"))

# LLM settings
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "300"))  # seconds

# Pattern discovery settings
MIN_PATTERN_EVENTS = int(os.getenv("MIN_PATTERN_EVENTS", "1"))
SIMILARITY_THRESHOLD = float(os.getenv("SIMILARITY_THRESHOLD", "0.7"))
MAX_PATTERNS = int(os.getenv("MAX_PATTERNS", "100"))

# Mitigation settings
MIN_SEVERITY_FOR_MITIGATION = int(os.getenv("MIN_SEVERITY_FOR_MITIGATION", "3"))

# Dashboard settings
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8888"))
AUTO_REFRESH_INTERVAL = int(os.getenv("AUTO_REFRESH_INTERVAL", "3"))

# Data retention
MAX_LOG_ENTRIES = int(os.getenv("MAX_LOG_ENTRIES", "1000"))
MAX_EVENTS_STORED = int(os.getenv("MAX_EVENTS_STORED", "500"))

# External feed URLs (optional, comma-separated)
_feeds_env = os.getenv("EXTERNAL_FEEDS", "")
EXTERNAL_FEEDS = [f.strip() for f in _feeds_env.split(",") if f.strip()]

# Set to False to disable Mastodon/live feed streaming at startup.
ENABLE_FEEDS = os.getenv("ENABLE_FEEDS", "false").lower() == "true"

# Log settings
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
AGENT_LOG_FILE = LOGS_DIR / "agent_log.json"
