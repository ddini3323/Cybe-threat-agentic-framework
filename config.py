"""
Configuration for CTI Agentic System
"""
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
POLLING_INTERVAL = 5  # seconds
MAX_EVENTS_PER_CYCLE = 5

# LLM settings
OLLAMA_MODEL = "llama3.2:3b"  # Fast local model
OLLAMA_HOST = "http://localhost:11434"
LLM_TIMEOUT = 300  # seconds

# Pattern discovery settings
# 1 = every single event forms a pattern and always gets a mitigation
MIN_PATTERN_EVENTS = 1
SIMILARITY_THRESHOLD = 0.7  # For clustering
MAX_PATTERNS = 100

# Mitigation settings
MIN_SEVERITY_FOR_MITIGATION = 3  # 1-5 scale

# Dashboard settings
WEB_HOST = "0.0.0.0"
WEB_PORT = 8888
AUTO_REFRESH_INTERVAL = 3  # seconds for dashboard

# Data retention
MAX_LOG_ENTRIES = 1000
MAX_EVENTS_STORED = 500

# External feed URLs (optional)
EXTERNAL_FEEDS = [
    # Example: "https://urlhaus.abuse.ch/downloads/csv_recent/",
    # Add your CTI feed URLs here
]

# Set to False to disable Mastodon/live feed streaming at startup.
# Useful when testing with manual input so feed events don't pollute the pipeline.
ENABLE_FEEDS = False

# Log settings
LOG_LEVEL = "INFO"
AGENT_LOG_FILE = LOGS_DIR / "agent_log.json"
