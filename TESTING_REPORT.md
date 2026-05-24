# CTI Agentic System — Testing Report
**Date:** 18 May 2026  
**System:** Real-Time Cyber Threat Intelligence (CTI) Agentic System  
**LLM:** Ollama llama3.2:3b (local, no internet required)  
**Framework:** Custom Python agents — FastAPI, ChromaDB, MITRE ATT&CK RAG  

---

## 1. System Overview

The CTI Agentic System is a multi-agent pipeline that automatically processes cyber threat intelligence from raw text input through six sequential stages, producing structured mitigations with MITRE D3FEND recommendations.

```
User Input (Text / JSON / CSV / File Upload)
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 1: Ingestion & Normalisation                     │
│  Parses input, assigns severity, extracts indicator     │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 2: Enrichment (Objective 1)                      │
│  LLM + MITRE ATT&CK RAG → IOCs, TTPs, CVEs, tactics    │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 3: Classifier (Objective 2)                      │
│  LLM → threat category, attack stage, asset category   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 4: Pattern Discovery                             │
│  Clusters events by TTP / malware / attack vector       │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 5: Mitigation Generator (Objective 3)            │
│  LLM → D3FEND-mapped steps, reasoning, sample rules    │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 6: Validation                                    │
│  Checks completeness, safety, and actionability         │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Web API | FastAPI (Python) | REST endpoints, dashboard serving |
| LLM | Ollama llama3.2:3b | Enrichment, classification, mitigation generation |
| Vector Store | ChromaDB | MITRE ATT&CK knowledge base storage |
| Embeddings | sentence-transformers/all-MiniLM-L6-v2 | RAG context retrieval |
| MITRE ATT&CK | Local JSON (691 techniques indexed) | TTP and tactic mapping |
| Async Runtime | Python asyncio | Non-blocking pipeline execution |
| Dashboard | HTML + JavaScript | Real-time pipeline visualisation |

> **Note:** No LangChain, LangGraph, or LangSmith used. All agents are custom Python classes with direct Ollama API calls. This keeps the system fully local and auditable.

---

## 3. Input Given for Testing

### Threat Description Submitted
```
APT29 spear-phishing campaign targeting NATO defence contractors via fake 
LinkedIn recruiter profiles at linkedin-recruiter-apt29.com. Victims 
redirected to credential harvesting page stealing Microsoft SSO tokens. 
Cobalt Strike beacon deployed to 185.220.101.55. CVE-2024-21338 exploited 
for privilege escalation. 73 confirmed victims, 8.3GB data exfiltrated.
```

### Why This Input Was Chosen
This represents a real-world Advanced Persistent Threat (APT) scenario with:
- A known threat actor (APT29 / Cozy Bear — Russian state-sponsored)
- A specific attack vector (LinkedIn social engineering)
- An active C2 server IP (`185.220.101.55` — Cobalt Strike beacon)
- An exploited CVE (`CVE-2024-21338` — Windows privilege escalation)
- Measurable impact (73 victims, 8.3GB exfiltrated)

### How Input Was Submitted
**Method 1 — Instant Pipeline (REST API):**
```
POST /api/ingest/instant
Content-Type: application/json
{ "text": "APT29 spear-phishing campaign..." }
```
Runs all 6 pipeline steps synchronously and returns the full result.

**Method 2 — Live Text Queue (REST API):**
```
POST /api/ingest/text
Content-Type: application/json
{ "text": "APT29 spear-phishing campaign..." }
```
Queues the event; the background pipeline processes it within 5 seconds.

---

## 4. Pipeline Execution — Step by Step

### Step 1: Ingestion & Normalisation

The system automatically parsed the raw text and produced a normalised `ThreatEvent`:

| Field | Value |
|---|---|
| Event ID | `d3fb347317ca1ff7` |
| Timestamp | 2026-05-18 22:10:07 |
| Source | Instant Submit |
| Type | IP (auto-detected from `185.220.101.55`) |
| Severity | **CRITICAL** (auto-inferred: text contains "APT", "exploit") |
| Indicator | `185.220.101.55` |

**How severity is inferred:**
```python
if any(w in text for w in ['apt', 'ransomware', 'zero-day', 'backdoor']):
    return SeverityLevel.CRITICAL   # Level 4
```

---

### Step 2: Enrichment — Objective 1 (O1)

The LLM (llama3.2:3b) analysed the raw text against the MITRE ATT&CK knowledge base (RAG-assisted) and extracted structured intelligence.

**Actual output produced:**

#### Indicators of Compromise (IOCs)
| Type | Value |
|---|---|
| IP | `185.220.101.55` (Cobalt Strike C2) |
| URL | `https://linkedin-recruiter-apt29.com/` |
| Domain | `linkedin-recruiter-apt29.com` |

#### CVEs Extracted
- `CVE-2024-21338` — Windows privilege escalation exploited post-phishing

#### MITRE ATT&CK TTPs
| TTP ID | Name |
|---|---|
| T1598 | Spearphishing Link |
| T1589 | Credentials (Gather Victim Identity Information) |
| T1059 | Command and Scripting Interpreter |

#### MITRE ATT&CK Tactics
| Tactic ID | Name |
|---|---|
| TA0001 | Initial Access |
| TA0002 | Execution |
| TA0003 | Obfuscation |

#### Summary
| Field | Value |
|---|---|
| Threat Category | Phishing |
| Attack Stage | Reconnaissance → Initial Access |
| Attack Vector | Spearphishing |
| Affected Assets | NATO defence contractors |
| Enrichment Confidence | **90%** |

---

### Step 3: Classification — Objective 2 (O2)

The classifier LLM applied structured threat categorisation.

**Actual output:**

| Field | Value |
|---|---|
| Threat Category | **APT** |
| Attack Stage | **Initial Access** |
| Affected Asset Category | **Enterprise IT** |
| Classification Confidence | **93%** |
| Severity Justification | *"The use of spear-phishing and exploitation of CVE-2024-21338 to gain initial access justify a CRITICAL severity classification."* |

---

### Step 4: Pattern Discovery

The pattern agent clustered events by shared TTPs and attack vectors. With two submissions of the same threat scenario, the following patterns were identified:

| Pattern ID | Pattern Name | Events | Severity |
|---|---|---|---|
| `f1fa39fa9a67f931` | TTP-Pattern-T1598 (Spearphishing Link) | 1 | CRITICAL |
| `3bb6a6933a170f36` | Attack-Spearphishing | 1 | CRITICAL |
| `4113bbc6565416af` | TTP-Pattern-T1598 (Phishing for Information) | 1 | CRITICAL |
| `83e59cda47ea865e` | Attack-Phishing | 1 | CRITICAL |

**Clustering logic:**
- Strategy 1: Group by primary TTP (`T1598`)
- Strategy 2: Group by malware family (none identified)
- Strategy 3: Group by attack vector (`Spearphishing`, `Phishing`)

---

### Step 5: Mitigation Generation — Objective 3 (O3)

The mitigation agent received each pattern and high-severity event, then generated MITRE D3FEND-mapped recommendations using chain-of-thought prompting.

**4 mitigations were generated and all passed validation:**

---

#### Mitigation 1 — Pattern-Based
**Title:** Prevent Spearphishing and Credential Theft  
**Priority:** CRITICAL (4)  
**Validated:** ✅ Yes  
**D3FEND:** `D3-MFA`, `D3-DNSDL`

**Reasoning (LLM chain-of-thought):**
> *"This phishing pattern exploits email trust to deliver malware. Blocking at the email gateway prevents delivery, while MFA limits credential theft impact. Network isolation stops lateral movement if a host is compromised."*

**Action Steps:**
1. Update DNS blocklists with identified malicious domains
2. Configure email gateway to quarantine emails from flagged senders
3. Enforce MFA on all accounts to limit credential theft impact
4. Monitor SIEM for authentication anomalies from affected users
5. Conduct targeted phishing awareness training

---

#### Mitigation 2 — Pattern-Based
**Title:** Layered Defense Against Spear Phishing  
**Priority:** EMERGENCY (5)  
**Validated:** ✅ Yes  
**D3FEND:** `D3-MFA`, `D3-DNSDL`

**Action Steps:**
1. Update DNS blocklists with identified malicious domains
2. Configure email gateway to quarantine emails from flagged senders
3. Enforce MFA on all accounts to limit credential theft impact
4. Implement process monitoring for suspicious activity
5. Conduct regular security awareness training

---

#### Mitigation 3 — Event-Based (High Severity Direct Path)
**Title:** APT29 Spear Phishing Campaign Containment  
**Priority:** EMERGENCY (5)  
**Validated:** ✅ Yes  
**D3FEND:** `D3-NTA`, `D3-UA`

**Reasoning (LLM chain-of-thought):**
> *"These steps address the immediate risk by containing and eradicating the Cobalt Strike beacon, detecting suspicious network traffic, and adding multi-factor authentication to prevent further exploitation."*

**Action Steps:**
1. Isolate affected network segments to prevent lateral movement *(Network Isolation)*
2. Deploy Network Traffic Analysis to monitor traffic to `185.220.101.55`
3. Implement MFA for all users to prevent credential harvesting
4. Scan endpoints for Cobalt Strike beacon and quarantine infected systems

---

#### Mitigation 4 — Event-Based (High Severity Direct Path)
**Title:** APT29 Spear-Phishing Campaign Containment  
**Priority:** EMERGENCY (5)  
**Validated:** ✅ Yes  
**D3FEND:** `D3-ITF`, `D3-UA`

**Reasoning (LLM chain-of-thought):**
> *"Immediate action is required to prevent further lateral movement and contain the threat, as confirmed victims are likely still within the network."*

**Action Steps:**
1. Block all outgoing traffic on ports 443/445 to prevent Cobalt Strike beacon deployment
2. Isolate all Windows endpoints associated with confirmed victims
3. Trigger alerting and incident response for all traffic from `185.220.101.55`

---

### Step 6: Validation

All 4 mitigations passed the automated validation checks:

| Check | Description | Result |
|---|---|---|
| Completeness | Has title, description, and ≥2 action steps | ✅ Pass |
| Safety | No dangerous commands (e.g. `rm -rf /`, `DROP TABLE`) | ✅ Pass |
| Scope | Not overly broad (e.g. "block all traffic") | ✅ Pass |

---

## 5. Full API Endpoint Test Results

| Endpoint | Method | Result | Response |
|---|---|---|---|
| `/api/health` | GET | ✅ | `{"status":"healthy","events_count":2,"patterns_count":4,"mitigations_count":4}` |
| `/api/ingest/text` | POST | ✅ | Event queued, ID returned |
| `/api/ingest/instant` | POST | ✅ | Full pipeline result returned |
| `/api/enriched-events` | GET | ✅ | 2 enriched events with IOCs/TTPs/CVEs |
| `/api/classifications` | GET | ✅ | APT, Initial Access, 93% confidence |
| `/api/patterns` | GET | ✅ | 4 patterns discovered |
| `/api/mitigations` | GET | ✅ | 4 mitigations, all validated |
| `/api/logs` | GET | ✅ | Full agent activity log |
| `/api/benchmark/run` | POST | ✅ | TTP extraction rate, confidence metrics |
| `/api/feeds` | GET | ✅ | Feed status (disabled by default) |
| `/api/pipeline/stop` | POST | ✅ | Pipeline paused |
| `/api/pipeline/start` | POST | ✅ | Pipeline resumed |

---

## 6. Issues Found During Testing and Fixes Applied

During testing, several issues were identified through code review and live testing. All were fixed.

### Issue 1 — Duplicate Ingestion on Server Restart (Critical)
**Problem:** The ingestion agent tracked processed files in a Python `set()` which was reset every time the server restarted. On restart, all files in `data/input/` were re-ingested, flooding the pipeline with duplicate events.  
**Fix:** Modified `agents/ingestion.py` to persist the processed file log to `data/.processed_files.json`. On restart, the agent loads this file and skips already-processed files.

### Issue 2 — File Upload Not Queued Immediately (High)
**Problem:** The `/api/ingest/file` endpoint saved uploaded files to disk but did not add events to the processing queue. Events would only be processed after the next polling cycle (up to 5 seconds later), and there was no immediate feedback.  
**Fix:** Rewrote the endpoint in `app.py` to parse the file immediately (CSV or JSON), create `ThreatEvent` objects, and add them directly to `state['pending_events']` with an immediate pipeline wake signal.

### Issue 3 — Mastodon Feeds Auto-Started on Boot (High)
**Problem:** Live Mastodon feeds (infosec.exchange) started automatically on every server boot, pulling external threat data that competed with user submissions for LLM processing slots.  
**Fix:** Added `ENABLE_FEEDS = False` in `config.py`. Feeds only start if explicitly enabled. Added `/api/feeds/enable` and `/api/feeds/disable` endpoints for runtime control.

### Issue 4 — No Mitigation for Single-Event Input (Medium)
**Problem:** The pattern discovery agent required `MIN_PATTERN_EVENTS = 2` to form a pattern. A single submitted threat would never produce a pattern, and therefore no mitigation was generated.  
**Fix:** Changed `MIN_PATTERN_EVENTS = 1` in `config.py`. Every enriched event now forms a pattern, and the mitigation agent always runs.

### Issue 5 — Chatbot Attribute Errors (Medium)
**Problem:** The chatbot was accessing `m.action` and `p.pattern_type` which do not exist on the Pydantic models. Correct fields are `m.title` and `p.pattern_name`.  
**Fix:** Updated all field references in `agents/chatbot.py` with defensive `_safe()` and `_safe_join()` helpers to handle unexpected LLM output types gracefully.

---

## 7. Mitigation Accuracy Assessment

| Aspect | Assessment |
|---|---|
| MFA enforcement | ✅ Correct — APT29 targets credential theft; MFA is highest-impact control |
| DNS blocklist for `linkedin-recruiter-apt29.com` | ✅ Correct — direct IOC, DNS block is right response |
| Network traffic monitoring for `185.220.101.55` | ✅ Correct — active C2 IP must be monitored and blocked |
| Cobalt Strike endpoint scan and isolation | ✅ Correct — beacon already deployed to 73 hosts |
| Network isolation to prevent lateral movement | ✅ Correct — exfiltration already occurred; containment needed |
| CVE-2024-21338 patch recommendation | ⚠️ Missing — patch for the exploited vulnerability was not explicitly mentioned |
| LinkedIn-specific social engineering awareness | ⚠️ Partial — training mentioned but not LinkedIn-specific |

**Overall accuracy: ~75%** — Core defensive actions are correct and actionable. Minor gaps in CVE patch recommendation and LinkedIn-specific controls.

---

## 8. Live Dashboard

The system provides a real-time web dashboard accessible at `http://localhost:8888`:

| Page | URL | Shows |
|---|---|---|
| Pipeline Overview | `/` | Live agent status, event counts, pipeline step |
| Live Input | `/live-input` | Submit threats; instant pipeline with results |
| Flow Tracker | `/flow-tracker` | Per-event step-by-step trace |
| Enrichment | `/enrichment` | All enriched events with IOCs, TTPs |
| Patterns | `/patterns` | Discovered attack patterns |
| Mitigations | `/mitigations` | Generated mitigations with D3FEND mapping |
| Benchmark | `/benchmark` | O4 evaluation metrics |

---

## 9. How to Run and Test

### Prerequisites
```
Python 3.10+
Ollama installed with llama3.2:3b model pulled
```

### Start the System
```powershell
cd C:\CTI-Agentic-System
$env:PYTHONUTF8="1"; python main.py
```

### Submit a Threat (Text)
```bash
curl -X POST http://localhost:8888/api/ingest/text \
  -H "Content-Type: application/json" \
  -d '{"text": "APT29 spear-phishing at linkedin-recruiter-apt29.com targeting NATO. Cobalt Strike C2 at 185.220.101.55. CVE-2024-21338 exploited."}'
```

### Submit and Get Instant Full Result
```bash
curl -X POST http://localhost:8888/api/ingest/instant \
  -H "Content-Type: application/json" \
  -d '{"text": "your threat description here"}'
```

### Check Pipeline Results
```bash
curl http://localhost:8888/api/health
curl http://localhost:8888/api/enriched-events
curl http://localhost:8888/api/patterns
curl http://localhost:8888/api/mitigations
```

---

## 10. Summary

The CTI Agentic System successfully demonstrated an end-to-end automated threat intelligence pipeline:

1. **Input** — A single natural language threat description was submitted
2. **Enrichment** — The local LLM extracted 3 IOCs, 1 CVE, 3 MITRE TTPs, and 3 tactics with 90% confidence
3. **Classification** — The threat was classified as APT / Initial Access with 93% confidence
4. **Pattern Discovery** — 4 attack patterns were identified by TTP and attack vector
5. **Mitigation** — 4 actionable mitigations were generated with MITRE D3FEND codes, reasoning, and step-by-step actions
6. **Validation** — All 4 mitigations passed automated safety and completeness checks

The system operates entirely locally using a small open-source LLM (llama3.2:3b) with no external API calls, making it suitable for air-gapped or classified environments.
