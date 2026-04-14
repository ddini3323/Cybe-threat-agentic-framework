# Real-Time Agentic Cyber Threat Intelligence System

A multi-agent CTI system powered by local LLMs (Ollama) that ingests, enriches, analyzes, and mitigates cyber threats in real time — with live streaming from public threat intelligence feeds.

## Features

- **5 Cooperating AI Agents** — Ingestion, Enrichment, Pattern Discovery, Mitigation, Validation
- **Local LLM Integration** — Uses Ollama (`llama3.2:3b`) for threat analysis, IOC extraction, and mitigation generation
- **Real-Time Feed Streaming** — Live data from URLhaus, ThreatFox, and Feodo Tracker (abuse.ch) — no API keys needed
- **8-Page Interactive Dashboard** — Dark SOC-style UI with per-agent color-coded pipeline visualization
- **Live Input** — Submit threats via JSON, CSV, free text, or file upload through the web UI
- **Human-in-the-Loop** — Approve or reject AI-generated mitigations before deployment
- **Flow Tracker** — Trace any event through all 5 pipeline stages

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Real-Time Feeds                           │
│  URLhaus (URLs) │ ThreatFox (IOCs) │ Feodo Tracker (C2 IPs)│
└────────┬────────┴────────┬─────────┴────────┬───────────────┘
         │                 │                  │
         ▼                 ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│  Agent 1: INGESTION (Cyan)                                  │
│  Normalizes CSV/JSON/text into ThreatEvent schema           │
├─────────────────────────────────────────────────────────────┤
│  Agent 2: ENRICHMENT (Yellow)              [LLM]            │
│  Extracts IOCs, TTPs, CVEs, attack vectors via LLM         │
├─────────────────────────────────────────────────────────────┤
│  Agent 3: PATTERN DISCOVERY (Orange)                        │
│  Groups related events by common TTPs/malware families      │
├─────────────────────────────────────────────────────────────┤
│  Agent 4: MITIGATION (Green)               [LLM]           │
│  Generates response actions and security rules              │
├─────────────────────────────────────────────────────────────┤
│  Agent 5: VALIDATION (Purple)                               │
│  Safety-checks mitigations for dangerous/overly broad rules │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│  FastAPI Dashboard (port 8888)                              │
│  8 pages: Overview, Ingestion, Enrichment, Patterns,        │
│  Mitigations, Flow Tracker, Live Input, Live Feeds          │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.ai/) installed and running
- 8GB+ RAM recommended

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Setup Ollama Model

```bash
ollama pull llama3.2:3b
```

Or run the setup script:

```bash
python setup_ollama.py
```

### 3. Start the System

```bash
python main.py
```

Open **http://localhost:8888** in your browser.

## Dashboard Pages

| Page | URL | Description |
|------|-----|-------------|
| **Pipeline Overview** | `/` | Animated pipeline with per-step color-coded progress |
| **Ingestion** | `/ingestion` | Raw events table, sources, severity charts |
| **Enrichment** | `/enrichment` | LLM-enriched events with IOCs, TTPs, CVEs |
| **Patterns** | `/patterns` | Discovered threat patterns with explanations |
| **Mitigations** | `/mitigations` | AI-generated responses with approve/reject buttons |
| **Flow Tracker** | `/flow-tracker` | Trace any event through all 5 pipeline stages |
| **Live Input** | `/live-input` | Submit threats via JSON, CSV, text, or file upload |
| **Live Feeds** | `/feeds` | Real-time streaming status from 3 public CTI feeds |

## Real-Time Streaming Feeds

The system connects to 3 free public threat intelligence feeds (no API keys required):

| Feed | Source | Data | Poll Interval |
|------|--------|------|---------------|
| **URLhaus** | abuse.ch | Malicious URLs (malware, phishing, exploit kits) | 2 min |
| **ThreatFox** | abuse.ch | IOCs (C2 IPs, malware hashes, domains) | 3 min |
| **Feodo Tracker** | abuse.ch | Botnet C2 server IPs (Emotet, TrickBot, etc.) | 5 min |

## Project Structure

```
CTI-Agentic-System/
├── main.py                    # Orchestrator — runs pipeline loop + web server
├── app.py                     # FastAPI server — REST API + page routes
├── config.py                  # Configuration (port, model, intervals, thresholds)
├── models.py                  # Pydantic data models (ThreatEvent, EnrichedEvent, etc.)
├── llm_wrapper.py             # Ollama LLM client wrapper
├── setup_ollama.py            # One-time Ollama + model setup script
├── requirements.txt
├── .gitignore
│
├── agents/
│   ├── __init__.py
│   ├── ingestion.py           # Agent 1: CSV/JSON normalization
│   ├── enrichment.py          # Agent 2: LLM-based IOC/TTP extraction
│   ├── pattern_discovery.py   # Agent 3: Threat pattern grouping
│   ├── mitigation.py          # Agent 4: LLM-generated mitigations
│   └── validation.py          # Agent 5: Safety validation
│
├── streaming/
│   ├── __init__.py
│   └── feeds.py               # Real-time feed streamer (URLhaus, ThreatFox, Feodo)
│
├── data/
│   └── input/                 # Drop CSV/JSON files here for ingestion
│       ├── sample_cti_feed.csv         # 15 threat indicators
│       └── sample_security_events.json # 12 security events
│
├── static/                    # Dashboard HTML pages
│   ├── dashboard.html         # Pipeline Overview
│   ├── ingestion.html         # Step 1
│   ├── enrichment.html        # Step 2
│   ├── patterns.html          # Step 3
│   ├── mitigations.html       # Steps 4-5
│   ├── flow-tracker.html      # Event flow tracer
│   ├── live-input.html        # Real-time input forms
│   └── feeds.html             # Streaming feed status
│
└── logs/                      # Runtime agent logs
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | System health + current pipeline step |
| GET | `/api/events` | All ingested events |
| GET | `/api/enriched-events` | LLM-enriched events |
| GET | `/api/patterns` | Discovered threat patterns |
| GET | `/api/mitigations` | Generated mitigations |
| GET | `/api/logs` | Agent activity logs |
| GET | `/api/feeds` | Streaming feed status |
| GET | `/api/pending` | Pending event count |
| GET | `/api/stats` | System statistics |
| POST | `/api/ingest/json` | Submit JSON event |
| POST | `/api/ingest/csv` | Submit CSV data |
| POST | `/api/ingest/text` | Submit free-text threat |
| POST | `/api/ingest/file` | Upload CSV/JSON file |
| POST | `/api/mitigations/{id}/status` | Approve/reject mitigation |

## Configuration

Edit `config.py`:

```python
OLLAMA_MODEL = "llama3.2:3b"        # Local LLM model
WEB_PORT = 8888                      # Dashboard port
POLLING_INTERVAL = 5                 # Pipeline cycle interval (seconds)
MAX_EVENTS_PER_CYCLE = 5             # Events enriched per cycle
MIN_SEVERITY_FOR_MITIGATION = 3      # Min severity for auto-mitigation
LLM_TIMEOUT = 300                    # LLM call timeout (seconds)
```

## Tech Stack

- **Backend**: Python 3.12, FastAPI, Uvicorn (async)
- **LLM**: Ollama + llama3.2:3b (local, no cloud APIs)
- **Frontend**: Vanilla HTML/CSS/JS (dark SOC theme, auto-refresh)
- **Streaming**: httpx async client polling abuse.ch feeds
- **Data Models**: Pydantic v2

## License

MIT
