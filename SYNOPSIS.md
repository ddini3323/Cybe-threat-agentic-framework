SYNOPSIS
========

Project Title: Context-Aware Cyber Threat Analytics and Mitigation Recommendation using Large Language Models (LLMs)


========================================
ABSTRACT
========================================

PARAGRAPH 1 — PROBLEM FORMULATION

Cyber threats are evolving at a pace that outstrips the capability of traditional signature-based and rule-based intrusion detection systems, which fail to adapt to novel, zero-day, and multi-stage attack patterns. Security Operations Centre (SOC) analysts are overwhelmed with unstructured threat data from heterogeneous sources including raw logs, OSINT feeds, CVE databases, and unstructured threat intelligence reports. No existing system provides a unified, end-to-end pipeline that ingests multi-source Cyber Threat Intelligence (CTI), enriches it with structured knowledge from frameworks such as MITRE ATT&CK, and automatically generates explainable, context-specific mitigation recommendations. Current approaches either stop at detection and alert generation, or are locked to specific domains such as IoT or transportation networks, leaving a critical gap in generalizable, actionable cyber threat response. This project addresses all four identified research gaps: the absence of a unified CTI pipeline, difficulty in processing heterogeneous threat data, lack of explainable mitigation output, and the practical failure of static detection systems against modern threats.

PARAGRAPH 2 — PROPOSED METHODOLOGY (TASK-WISE)

The proposed system is a six-stage multi-agent pipeline built entirely in Python with local Large Language Model (LLM) inference via Ollama (llama3.2:3b), ensuring operation in air-gapped environments without any external API dependency. Agent 1 (Ingestion) normalises multi-format input — free text, JSON, CSV, and file uploads — into a standardised ThreatEvent schema with automatic severity classification. Agent 2 (Enrichment) uses Retrieval-Augmented Generation (RAG) over a locally indexed MITRE ATT&CK knowledge base (691 techniques in ChromaDB) to extract Indicators of Compromise (IOCs), CVEs, MITRE TTPs, and tactics from raw threat text using LLM reasoning. Agent 3 (Classifier) applies LLM contextual reasoning to classify each enriched event by threat category, MITRE ATT&CK kill-chain stage, affected asset category, and confidence score. Agent 4 (Pattern Discovery) clusters events by shared TTPs, malware families, and attack vectors to identify recurring attack patterns. Agent 5 (Mitigation Generator) produces ranked, explainable mitigation recommendations mapped to MITRE D3FEND defensive countermeasures with chain-of-thought justification, and Agent 6 (Validation) applies automated safety and completeness checks before analyst delivery. A real-time dashboard (FastAPI + HTML/CSS/JS) provides pipeline visualisation, live event submission, and a benchmarking interface for system evaluation.

PARAGRAPH 3 — RESULTS AND CONCLUSIONS

Live testing with a real-world APT29 spear-phishing scenario demonstrated successful end-to-end pipeline execution: the Enrichment Agent extracted three IOCs, one CVE (CVE-2024-21338), and three MITRE ATT&CK TTPs (T1598, T1589, T1059) with 90% enrichment confidence. The Classifier Agent categorised the threat as APT / Initial Access with 93% classification confidence. Four attack patterns were discovered and four MITRE D3FEND-mapped mitigations were generated (including MFA enforcement, DNS blocklist updates, network traffic analysis, and Cobalt Strike beacon containment), all of which passed automated validation checks. The Benchmark Agent recorded a TTP Extraction Rate of 100%, an Average Enrichment Confidence of 0.90, an Average Classification Confidence of 0.93, and a High-Severity Coverage of 100%. The system demonstrated that a fully local, privacy-preserving, multi-agent LLM pipeline can successfully address the four identified research gaps by providing context-aware, explainable, and actionable cyber threat intelligence from raw input to validated mitigation — without any cloud dependency or proprietary API cost.


========================================
REQUIREMENT SPECIFICATION
========================================

HARDWARE REQUIREMENTS

Minimum (Functional):
  - Processor   : Intel Core i5 (8th generation) or AMD Ryzen 5, or equivalent
  - RAM         : 8 GB (minimum for running Ollama llama3.2:3b locally)
  - Storage     : 10 GB free disk space (3 GB model + 5 GB MITRE ATT&CK index + application)
  - Network     : Not required (fully offline capable)

Recommended (Optimal Performance):
  - Processor   : Intel Core i7 / AMD Ryzen 7, 8 cores or higher
  - RAM         : 16 GB or above
  - GPU         : Optional — NVIDIA GPU with CUDA support for accelerated Ollama inference
  - Storage     : 20 GB SSD
  - Network     : Local LAN for multi-user dashboard access

Tested Environment:
  - OS          : Windows 11 Enterprise (10.0.26200)
  - RAM         : 16 GB
  - Processor   : x86-64 architecture

----

SOFTWARE REQUIREMENTS

  - Operating System    : Windows 10/11, Ubuntu 20.04+, or macOS 12+
  - Python              : Version 3.10 or higher
  - Ollama              : Version 0.3+ (local LLM inference engine)
  - LLM Model           : llama3.2:3b (pulled via Ollama — 2.0 GB)
  - Web Browser         : Google Chrome, Mozilla Firefox, or Microsoft Edge (for dashboard)

Python Libraries (pip install -r requirements.txt):
  - fastapi             : REST API and web server framework
  - uvicorn             : ASGI server for FastAPI
  - pydantic            : Data schema validation
  - httpx               : Async HTTP client for Ollama API calls
  - chromadb            : Vector database for MITRE ATT&CK RAG
  - sentence-transformers: Text embeddings (all-MiniLM-L6-v2)
  - python-multipart    : File upload handling
  - mastodon.py         : Real-time social threat feed streaming (optional)

----

USER REQUIREMENTS

  - UR1: The user (SOC analyst) must be able to submit a threat description as free text, JSON, or CSV file through a web interface without requiring technical knowledge of the underlying pipeline.
  - UR2: The user must receive an enriched output containing identified IOCs, CVEs, and MITRE ATT&CK TTP IDs within seconds of submission.
  - UR3: The user must receive a ranked list of actionable mitigation steps with plain-language explanations describing why each countermeasure applies to the specific threat.
  - UR4: The user must be able to view the pipeline processing status and individual agent activity logs in real time through a dashboard.
  - UR5: The user must be able to trigger a system benchmark to evaluate pipeline performance metrics at any time.
  - UR6: The system must operate entirely locally — no data must be sent to external servers or cloud APIs.

----

SYSTEM REQUIREMENTS

  - SR1: The system must normalise all input formats (text, JSON, CSV) into a unified ThreatEvent schema and automatically assign a severity level (LOW / MEDIUM / HIGH / CRITICAL / EMERGENCY).
  - SR2: The system must query a locally indexed MITRE ATT&CK knowledge base (ChromaDB vector store, 691 techniques) using semantic search to retrieve relevant TTPs for every threat event.
  - SR3: The system must classify each enriched event by threat category, MITRE ATT&CK kill-chain stage, and affected asset category using LLM contextual reasoning with a reported confidence score.
  - SR4: The system must generate at least one MITRE D3FEND-mapped mitigation for every HIGH-severity or above event, with chain-of-thought justification and ranked action steps.
  - SR5: All generated mitigations must pass automated validation checks for completeness (title + description + minimum 2 steps), safety (no dangerous commands), and scope (not overly broad).
  - SR6: The system must compute and report five benchmark metrics: TTP Extraction Rate, Average Enrichment Confidence, Average Classification Confidence, Mitigation Relevance Score, and High-Severity Coverage.
  - SR7: The pipeline must support both synchronous (instant, single-request) and asynchronous (background polling, every 5 seconds) processing modes.
  - SR8: The system must prevent duplicate event ingestion across server restarts through persistent file tracking.


========================================
OBJECTIVES
========================================

All four objectives have been fully implemented and validated through live system testing.

OBJECTIVE 1 — Context-Aware Threat Ingestion Pipeline (ACHIEVED)
  Description : Ingest multi-source CTI (logs, OSINT feeds, CVE/NVD data) and enrich each
                threat event with MITRE ATT&CK TTP mappings using RAG over the ATT&CK
                knowledge base.
  Research Gap: Gaps identified in P7 (CTIArena, Cheng et al., 2025) and P9 (Ferrag et al.,
                2024) — no unified pipeline linking CTI ingestion, context enrichment, and
                mitigation recommendation.
  Implemented : EnrichmentAgent (agents/enrichment.py) uses ChromaDB RAG over 691 MITRE
                ATT&CK techniques (indexed via sentence-transformers all-MiniLM-L6-v2) to
                extract IOCs, CVEs, TTPs, and tactics from any input format. Achieved 90%
                enrichment confidence in live testing.

OBJECTIVE 2 — LLM-Powered Threat Classification Module (ACHIEVED)
  Description : Classify threats by type, severity level, attack stage, and affected asset
                category using LLM contextual reasoning — not static signature matching.
  Research Gap: Gaps identified in P2 (Hasanov et al., 2024), P5 (Elouardi et al., 2024),
                and P10 (Feng & Sakurai, 2025) — practical deployment of intelligent,
                generalizable detection systems remains unsolved.
  Implemented : ClassifierAgent (agents/classifier.py) uses LLM to assign threat category
                (14 categories), MITRE ATT&CK kill-chain stage (14 stages), asset category
                (9 categories), severity justification, and a classification confidence score.
                Achieved 93% classification confidence in live testing (APT / Initial Access).

OBJECTIVE 3 — Explainable Mitigation Recommendation Engine (ACHIEVED)
  Description : Generate context-specific, ranked mitigation recommendations with
                chain-of-thought justification aligned to MITRE D3FEND and NIST CSF.
  Research Gap: Gaps identified in P1 (Hmimou et al., 2025), P4 (Melhem et al., 2025), and
                P8 (FALCON, Mitra et al., 2025) — no system generates explainable,
                D3FEND-mapped mitigation steps from CTI context.
  Implemented : MitigationAgent (agents/mitigation.py) uses chain-of-thought prompting to
                generate ranked action steps with MITRE D3FEND codes (D3-MFA, D3-DNSDL,
                D3-NTA, D3-ITF, D3-UA, D3-EDR) and plain-language reasoning. ValidationAgent
                applies completeness, safety, and scope checks. 4/4 mitigations validated
                in live testing.

OBJECTIVE 4 — System Evaluation and Benchmarking (ACHIEVED)
  Description : Evaluate performance against real CTI datasets and MITRE ATT&CK evaluations;
                measure enrichment quality, classification accuracy, and mitigation relevance.
  Research Gap: Gaps identified in P7 (CTIArena, Cheng et al., 2025) and P3 (Salek et al.,
                2025) — no systematic evaluation framework exists for context-aware CTI
                pipelines.
  Implemented : EvaluatorAgent (agents/evaluator.py) computes 5 metrics — TTP Extraction
                Rate, Average Enrichment Confidence, Average Classification Confidence,
                Mitigation Relevance (LLM self-evaluation), and High-Severity Coverage.
                Accessible via POST /api/benchmark/run and visualised on /benchmark dashboard.
                Live results: TTP Rate 100%, Enrichment Confidence 0.90, Classification
                Confidence 0.93, High-Severity Coverage 100%.


========================================
METHODOLOGY
========================================

The system follows a sequential six-stage multi-agent architecture where each agent is a
discrete Python class responsible for one pipeline stage. All agents communicate through a
shared application state dictionary (FastAPI) and produce structured Pydantic model outputs
that feed into the next stage.

STAGE 1 — INGESTION AND NORMALISATION
  The IngestionAgent accepts multi-format input (plain text, JSON, CSV, file uploads) from
  the web interface or the REST API. It normalises all inputs into a ThreatEvent schema
  containing a unique event ID, timestamp, raw text, detected indicator (IP, domain, URL,
  hash), event type, and severity level. Severity is automatically inferred from keywords
  (e.g., "APT", "ransomware", "zero-day" → CRITICAL). Processed files are tracked in a
  persistent JSON log to prevent duplicate ingestion across server restarts.

STAGE 2 — ENRICHMENT WITH MITRE ATT&CK RAG (Objective 1)
  The EnrichmentAgent submits each ThreatEvent to the local LLM (llama3.2:3b via Ollama)
  alongside retrieved context from a ChromaDB vector database containing 691 MITRE ATT&CK
  techniques, indexed using sentence-transformers (all-MiniLM-L6-v2). The RAG retriever
  performs semantic search to find the most relevant techniques for the input text and
  provides them as grounding context. The LLM then extracts: IOCs (IP addresses, domains,
  URLs, hashes), CVE identifiers, MITRE ATT&CK TTP IDs and names, tactic names, malware
  family, attack vector, threat summary, and an enrichment confidence score (0–1).

STAGE 3 — THREAT CLASSIFICATION (Objective 2)
  The ClassifierAgent receives each enriched event and applies a structured classification
  prompt to the LLM. The prompt includes the raw threat text, extracted TTPs, IOCs, CVEs,
  malware family, and attack vector, and asks the model to select from predefined lists of
  14 threat categories, 14 MITRE ATT&CK kill-chain stages, and 9 asset categories. The
  output includes a severity justification and a classification confidence score, which is
  stored as a ThreatClassification Pydantic model.

STAGE 4 — PATTERN DISCOVERY
  The PatternDiscoveryAgent clusters enriched events by three strategies: primary TTP
  grouping (events sharing the same leading TTP), malware family grouping (events attributed
  to the same malware), and attack vector grouping (events sharing the same vector such as
  "spearphishing"). Each cluster forms a named ThreatPattern with an aggregated severity
  level and a list of associated event IDs. The minimum cluster size is set to 1, ensuring
  every single event produces at least one pattern.

STAGE 5 — MITIGATION GENERATION (Objective 3)
  The MitigationAgent processes each identified pattern and each high-severity event
  individually. For each input, it constructs a detailed chain-of-thought prompt containing
  the threat context, TTPs, IOCs, severity, and asset category, then instructs the LLM to
  produce: a mitigation title, plain-language reasoning (why this countermeasure is
  appropriate), a prioritised list of action steps, and MITRE D3FEND defensive technique
  codes. Pattern-based mitigations address the recurring attack cluster; event-based
  mitigations address the specific high-severity incident. All mitigations are stored as
  MitigationAction Pydantic models.

STAGE 6 — VALIDATION
  The ValidationAgent applies three automated checks to every generated mitigation:
  (1) Completeness — must contain a title, description, and at least two action steps;
  (2) Safety — must not contain dangerous commands such as "rm -rf", "DROP TABLE", or
  "shutdown"; (3) Scope — must not be overly broad (e.g., "block all traffic"). Mitigations
  that fail any check are flagged with failure reasons; those that pass are marked validated
  and forwarded to the analyst dashboard.

BENCHMARKING (Objective 4)
  The EvaluatorAgent computes five quantitative metrics on demand: TTP Extraction Rate
  (proportion of events with extracted TTPs), Average Enrichment Confidence, Average
  Classification Confidence, Mitigation Relevance Score (LLM self-evaluation of mitigation
  appropriateness to source event), and High-Severity Coverage (proportion of CRITICAL and
  EMERGENCY events that received a validated mitigation). Results are stored historically
  and displayed on the /benchmark dashboard with progress bars and a run history table.


========================================
EXPECTED OUTCOME
========================================

  1. A fully functional, locally deployable multi-agent CTI system that processes raw
     cyber threat descriptions and produces structured, validated intelligence outputs
     without any external API dependency or cloud connection.

  2. Automatic MITRE ATT&CK enrichment of every submitted threat event — extracting IOCs,
     CVEs, TTP IDs, tactic names, malware family, and attack vector — with a reported
     enrichment confidence score above 0.85 on real-world threat scenarios.

  3. LLM-based threat classification assigning each event a threat category, kill-chain
     stage, and asset category with a classification confidence score, demonstrating
     that contextual LLM reasoning outperforms static signature-based categorisation.

  4. Explainable mitigation recommendations for every high-severity event, mapped to MITRE
     D3FEND defensive techniques, with chain-of-thought reasoning that explains why each
     countermeasure is appropriate — directly addressing the lack of explainability identified
     in P1 (Hmimou et al.) and P4 (Melhem et al., LENS).

  5. A quantitative benchmark demonstrating system performance across five metrics, with
     TTP Extraction Rate ≥ 90%, High-Severity Coverage = 100%, and Mitigation Relevance
     Score ≥ 0.75 on tested threat scenarios.

  6. A generalizable system architecture that handles APT, ransomware, phishing, DDoS,
     supply chain, and web application threat types — solving the domain-locking limitation
     identified in P3 (Salek et al.) and P6 (Mahmood et al.).


========================================
TECHNOLOGIES USED
========================================

  Technology                 Purpose
  -------------------------  --------------------------------------------------------
  Python 3.10+               Core programming language
  FastAPI                    REST API backend and web server
  Uvicorn                    ASGI server for asynchronous request handling
  Ollama + llama3.2:3b       Local LLM inference (no API cost, air-gapped capable)
  ChromaDB                   Vector database for MITRE ATT&CK RAG
  sentence-transformers      Text embeddings for semantic search (all-MiniLM-L6-v2)
  MITRE ATT&CK STIX Bundle   Threat knowledge base (691 techniques, indexed locally)
  Pydantic                   Data validation and structured schema models
  HTML / CSS / JavaScript    8-page real-time SOC dashboard (dark mode)
  Mastodon.py                Optional real-time social threat feed streaming


========================================
HOW TO RUN THE PROJECT
========================================

Step 1 — Install Ollama
  Download and install Ollama from https://ollama.com
  Then pull the LLM model:
    ollama pull llama3.2:3b

Step 2 — Install Python Dependencies
  pip install -r requirements.txt

Step 3 — Start the System
  Windows:
    set PYTHONUTF8=1
    python main.py

  Linux / macOS:
    PYTHONUTF8=1 python main.py

Step 4 — Open the Dashboard
  Browser: http://localhost:8888

Step 5 — Submit a Threat
  Go to: http://localhost:8888/live-input
  Paste any threat description in the text box and click Submit.
  The full pipeline (Ingest → Enrich → Classify → Pattern → Mitigate → Validate)
  runs and results appear within seconds.


========================================
PROJECT INFORMATION
========================================

  Project Title  : Context-Aware Cyber Threat Analytics and Mitigation
                   Recommendation using Large Language Models
  Domain         : Cyber Security / Artificial Intelligence
  Framework Type : Multi-Agent Agentic System
  LLM Used       : Ollama llama3.2:3b (local, open-source)
  No. of Agents  : 6 (Ingestion, Enrichment, Classifier, Pattern Discovery,
                   Mitigation, Validation) + Evaluator + Chatbot
  Dashboard Pages: 8 (Pipeline Overview, Live Input, Flow Tracker, Enrichment,
                   Patterns, Mitigations, Benchmark, Feeds)
  API Endpoints  : 15+ REST endpoints
  Knowledge Base : MITRE ATT&CK (691 techniques), MITRE D3FEND, NVD/CVE
  Generated      : May 2026
