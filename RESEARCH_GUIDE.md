# Context-Aware Cyber Threat Analytics & Mitigation Recommendation using LLMs
## Complete Research Guide — Literature Survey, Papers, Objectives & Demo Plan

---

## HOW TO DOWNLOAD PAPERS

### IEEE Access Papers (Free — No Login Required)
1. Go to [https://ieeexplore.ieee.org](https://ieeexplore.ieee.org)
2. Paste the paper title in the search bar
3. Click the paper → look for the **green "Open Access"** badge
4. Click **PDF** — downloads immediately for free

### arXiv Papers (Free — Direct PDF)
- Add `/pdf/` before the arXiv ID in the URL
- Example: `https://arxiv.org/pdf/2405.12750` → downloads PDF directly

---

## 10 Open-Access Papers

| # | Title | Authors | Year | Venue | Download Link |
|---|-------|---------|------|-------|---------------|
| P1 | A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models | Hmimou, Tabaa, Khiat, Hidila | 2025 | **IEEE Access** | https://ieeexplore.ieee.org/document/11141466 |
| P2 | Application of Large Language Models in Cybersecurity: A Systematic Literature Review | Hasanov, Virtanen, Hakkala, Isoaho | 2024 | **IEEE Access** | https://ieeexplore.ieee.org/document/10767242 |
| P3 | A LLM-Supported Threat Modeling Framework for Transportation Cyber-Physical Systems | Salek, Chowdhury, Munir et al. | 2025 | **IEEE Access** | https://ieeexplore.ieee.org/document/11143218 |
| P4 | LENS: Lightweight and Explainable LLM-Based APT Detection at the Edge for 6G Security | Melhem, Golec, Alwarafy et al. | 2025 | **IEEE Access** | https://ieeexplore.ieee.org/document/11184805 |
| P5 | A Survey on Hybrid-CNN and LLMs for Intrusion Detection Systems | Elouardi, Motii, Jouhari et al. | 2024 | **IEEE Access** | https://ieeexplore.ieee.org/document/10767686 |
| P6 | LLM-Enhanced Security Framework for IoT: Anomaly Detection and Malicious Device Identification | Mahmood, Ashab, Sohan et al. | 2025 | **IEEE Access** | https://ieeexplore.ieee.org/document/11175688 |
| P7 | CTIArena: Benchmarking LLM Knowledge and Reasoning Across Heterogeneous Cyber Threat Intelligence | Cheng, Liu, Li, Song, Gao | 2025 | arXiv cs.CR | https://arxiv.org/pdf/2510.11974 |
| P8 | FALCON: Autonomous CTI Mining with LLMs for IDS Rule Generation | Mitra, Bazarov, Duclos, Mittal et al. | 2025 | arXiv cs.CR | https://arxiv.org/pdf/2508.18684 |
| P9 | Generative AI in Cybersecurity: A Comprehensive Review of LLM Applications and Vulnerabilities | Ferrag, Alwahedi, Battah et al. | 2024 | arXiv cs.CR | https://arxiv.org/pdf/2405.12750 |
| P10 | Network Intrusion Detection: Evolution from Conventional Approaches to LLM Collaboration | Feng, Sakurai | 2025 | arXiv cs.CR | https://arxiv.org/pdf/2510.23313 |

---

## Literature Survey Table (4 Columns — Copy Directly into Report)

| Paper Title & Reference | Authors & Year | Methodology / Approach | Research Gap Identified |
|-------------------------|---------------|------------------------|------------------------|
| A Multi-Agent System for Cybersecurity Threat Detection Using LLMs [P1] | Hmimou et al., 2025, IEEE Access | Multi-agent LLM architecture with contextual threat correlation engine | No MITRE ATT&CK enrichment; lacks explainable mitigation recommendations for SOC analysts |
| Application of LLMs in Cybersecurity: Systematic Literature Review [P2] | Hasanov et al., 2024, IEEE Access | Survey of 73 papers across all LLM security use cases | Practical real-world deployment of end-to-end LLM pipelines (detection → response) remains under-explored |
| LLM-Supported Threat Modeling for Cyber-Physical Systems [P3] | Salek et al., 2025, IEEE Access | LLM + MITRE ATT&CK for transportation domain threat modeling | Domain-specific only (transportation); no generalizable context-aware framework for multi-domain threats |
| LENS: Explainable LLM-Based APT Detection for 6G Security [P4] | Melhem et al., 2025, IEEE Access | Lightweight LLM + XAI layer for edge APT detection | Explainability limited to detection phase; no downstream mitigation recommendation or response action generation |
| Survey on Hybrid-CNN and LLMs for Intrusion Detection Systems [P5] | Elouardi et al., 2024, IEEE Access | CNN-LLM hybrid taxonomy across recent IoT benchmark datasets | No unified integration of CTI knowledge bases (NVD/ATT&CK) with detection models for context enrichment |
| LLM-Enhanced Security Framework for IoT Anomaly Detection [P6] | Mahmood et al., 2025, IEEE Access | LLM fine-tuned on IoT logs for anomaly and malicious device detection | IoT-specific; cannot process unstructured CTI reports; output is alert-only with no mitigation guidance |
| CTIArena: Benchmarking LLMs on Heterogeneous CTI [P7] | Cheng et al., 2025, arXiv | Multi-task benchmark spanning 9 CTI tasks evaluated on 10 LLMs | Most LLMs struggle with multi-source heterogeneous CTI; domain-tailored LLMs and RAG augmentation required |
| FALCON: Autonomous CTI Mining with LLMs for IDS Rules [P8] | Mitra et al., 2025, arXiv | Autonomous LLM pipeline generating Snort + YARA rules from CTI text | Generates detection rules only; no human-readable mitigation strategy or context-aware response plan |
| Generative AI in Cybersecurity: Comprehensive LLM Review [P9] | Ferrag et al., 2024, arXiv | Review of 42 LLMs across IDS, malware, CVE, RAG technique evaluation | Identifies absence of a unified RAG pipeline linking CTI ingestion, context enrichment, and mitigation recommendation |
| Network IDS: Conventional to LLM Collaboration [P10] | Feng & Sakurai, 2025, arXiv | Survey of signature-based, ML, and LLM-based NIDS evolution | Neural network NIDS has poor real-world deployment; LLMs face exploitation risks; domain-specific NIDS LLMs remain impractical |

---

## Problem Statement — 4 Points (Cite These in Your Presentation)

**1. Static detection systems fail against novel and evolving threats** *(Source: P2, P10)*
> Existing signature-based and rule-based intrusion detection systems (IDS) cannot adapt to new or zero-day attack patterns. Hasanov et al. (2024) and Feng & Sakurai (2025) identify that the practical deployment of intelligent, generalizable detection systems across diverse threat types remains an unsolved challenge in real-world production environments.

**2. No unified pipeline exists from CTI ingestion to actionable mitigation** *(Source: P8, P9)*
> FALCON (Mitra et al., 2025) addresses CTI-to-rule generation in isolation, and Ferrag et al. (2024) confirm no single framework integrates multi-source CTI ingestion, MITRE ATT&CK context enrichment, and explainable mitigation recommendations end-to-end.

**3. LLMs struggle with heterogeneous, multi-source threat data** *(Source: P7)*
> CTIArena (Cheng et al., 2025) demonstrates that most state-of-the-art LLMs perform poorly on multi-source CTI tasks (structured threat feeds, unstructured reports, raw logs) without domain-specific knowledge augmentation via RAG. Threats are processed in isolation rather than as fused contextual intelligence.

**4. Mitigation recommendations lack explainability and context-specificity** *(Source: P1, P4)*
> Multi-agent systems (Hmimou et al., 2025) and LENS (Melhem et al., 2025) generate alerts and detections but do not explain *why* a specific countermeasure applies to the current deployment context. This reduces analyst trust and slows SOC decision-making in time-critical scenarios.

---

## 4 Project Objectives

| # | Objective | Description | Gap Addressed |
|---|-----------|-------------|--------------|
| **O1** | Context-Aware Threat Ingestion Pipeline | Ingest multi-source CTI (logs, OSINT feeds, CVE/NVD data) and enrich each threat event with MITRE ATT&CK TTP mappings using RAG over the ATT&CK knowledge base | Gaps in P7, P9 |
| **O2** | LLM-Powered Threat Classification Module | Classify threats by type, severity level, attack stage, and affected asset category using LLM contextual reasoning — not static signature matching | Gaps in P2, P5, P10 |
| **O3** | Explainable Mitigation Recommendation Engine | Generate context-specific, ranked mitigation recommendations with chain-of-thought justification aligned to MITRE D3FEND and NIST CSF frameworks | Gaps in P1, P4, P8 |
| **O4** | System Evaluation and Benchmarking | Evaluate performance against real CTI datasets and MITRE ATT&CK evaluations; measure precision, recall, F1, and recommendation relevance score | Gaps in P7, P3 |

---

## Future Enhancements from Papers (Implemented in This Project)

| Enhancement | Source Paper | Implementation in This Project |
|-------------|-------------|-------------------------------|
| Domain-tailored LLM for CTI tasks | P7 (CTIArena) | Fine-tuned prompt engineering with MITRE ATT&CK domain context |
| RAG-based unified CTI pipeline | P9 (Ferrag et al.) | ChromaDB + sentence-transformers over MITRE ATT&CK knowledge base |
| Explainable mitigation with reasoning layer | P4 (LENS), P1 (Hmimou) | Chain-of-thought prompting in mitigation agent |
| Autonomous IDS rule generation from CTI | P8 (FALCON) | Snort/YARA rule generation as part of mitigation output |
| Multi-source CTI fusion | P3 (Salek), P7 | Logs + CVE feeds + threat reports processed as unified context |

---

## Demo Plan for Lectures (4 Screens)

### Screen 1 — Threat Input
- Show the **Live Input page**: paste a threat log, CVE ID, or raw CTI text
- Options: JSON input, free text, file upload
- URL: `http://localhost:8888/live-input`

### Screen 2 — Enrichment Output
- Switch to **Enrichment page** to show LLM extraction results
- Shows: Threat type, severity, MITRE ATT&CK Tactic/Technique, extracted IOCs, CVEs, malware family
- URL: `http://localhost:8888/enrichment`

### Screen 3 — Mitigation Recommendation
- Switch to **Mitigations page** to show generated recommendations
- Shows: Ranked mitigation steps + plain-language explanation (*why* this countermeasure)
- Generated Snort/YARA rule example
- URL: `http://localhost:8888/mitigations`

### Screen 4 — Dashboard Overview
- Show the **Dashboard** with animated 5-step pipeline status
- Real-time agent activity logs
- Statistics: total events processed, patterns found, mitigations generated
- URL: `http://localhost:8888`

---

## How to Run the Project

```bash
# 1. Install Ollama (https://ollama.com)
ollama pull llama3.2:3b

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start the system
python main.py

# 4. Open the dashboard
# Browser: http://localhost:8888
```

---

## System Architecture Summary

```
INPUT SOURCES
  ├── File drops (CSV/JSON) → data/input/
  ├── Live Web UI (JSON, CSV, text, file upload)
  └── Real-time feeds (Mastodon infosec.exchange)
          │
          ▼
AGENT 1: INGESTION — Normalize to ThreatEvent schema
          │
          ▼
AGENT 2: ENRICHMENT — LLM + RAG (MITRE ATT&CK + ChromaDB)
          │            Extracts: IOCs, CVEs, TTPs, attack vector
          ▼
AGENT 3: PATTERN DISCOVERY — Cluster events by TTP/malware/vector
          │
          ▼
AGENT 4: MITIGATION — LLM generates ranked, explainable recommendations
          │            With Snort/YARA rule examples
          ▼
AGENT 5: VALIDATION — Safety check before analyst review
          │
          ▼
OUTPUT: Dashboard (http://localhost:8888) + REST API
```

---

## Key Technologies Used

| Technology | Purpose |
|-----------|---------|
| Python + FastAPI | Backend REST API and web server |
| Ollama + llama3.2:3b | Local LLM inference (no API cost) |
| ChromaDB | Vector database for RAG |
| sentence-transformers (all-MiniLM-L6-v2) | Text embeddings for semantic search |
| MITRE ATT&CK STIX Bundle | Threat knowledge base (33MB, cached locally) |
| Pydantic | Data validation and schema models |
| HTML/CSS/JS | 8-page interactive dark-mode SOC dashboard |

---

## Additional Open-Access Resources

| Resource | URL |
|----------|-----|
| MITRE ATT&CK Framework | https://attack.mitre.org |
| MITRE D3FEND (Defensive Countermeasures) | https://d3fend.mitre.org |
| NVD (CVE Database) | https://nvd.nist.gov |
| NIST Cybersecurity Framework | https://www.nist.gov/cyberframework |
| CISA Known Exploited Vulnerabilities | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| OpenCTI (Open Source CTI Platform) | https://github.com/OpenCTI-Platform/opencti |

---

*Generated: 2026-05-17 | Project: Context-Aware Cyber Threat Analytics and Mitigation Recommendation using LLMs*
