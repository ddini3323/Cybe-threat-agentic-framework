# Citations Reference — CTI Agentic System Project
## All 30 Papers + 4 Objectives | Use this file while writing each chapter

---

## PART 1 — IEEE Papers (20 Papers)

| # | Title | Authors | Year | Venue | Type | What It Does | Gap for Our Project | Link |
|---|-------|---------|------|-------|------|-------------|--------------------|----|
| P1 | A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using LLMs | Hmimou, Tabaa, Khiat, Hidila | 2025 | IEEE Access | Original Research | Multi-agent LLM architecture with threat correlation engine | No MITRE enrichment; no explainable mitigation output | https://ieeexplore.ieee.org/document/11141466 |
| P2 | Application of LLMs in Cybersecurity: Systematic Literature Review | Hasanov, Virtanen, Hakkala, Isoaho | 2024 | IEEE Access | Survey/Review | Surveys 73 papers across all LLM security use cases | End-to-end unified pipeline (detect → respond) not deployed in practice | https://ieeexplore.ieee.org/document/10767242 |
| P3 | A LLM-Supported Threat Modeling Framework for Transportation CPS | Salek, Chowdhury, Munir et al. | 2025 | IEEE Access | Original Research | LLM + MITRE ATT&CK for transportation domain threat modeling | Domain-locked (transportation only); no generalizable multi-domain pipeline | https://ieeexplore.ieee.org/document/11143218 |
| P4 | LENS: Lightweight Explainable LLM-Based APT Detection at the Edge for 6G | Melhem, Golec, Alwarafy et al. | 2025 | IEEE Access | Original Research | LLM + XAI for edge APT detection in 6G networks | Explainability stops at detection; no mitigation or response action generated | https://ieeexplore.ieee.org/document/11184805 |
| P5 | A Survey on Hybrid-CNN and LLMs for Intrusion Detection Systems | Elouardi, Motii, Jouhari et al. | 2024 | IEEE Access | Survey | CNN-LLM hybrid taxonomy across IoT IDS benchmarks | No unified CTI knowledge base (NVD/ATT&CK) integration for enrichment | https://ieeexplore.ieee.org/document/10767686 |
| P6 | LLM-Enhanced Security Framework for IoT: Anomaly Detection and Malicious Device Identification | Mahmood, Ashab, Sohan et al. | 2025 | IEEE Access | Original Research | LLM fine-tuned on IoT logs for anomaly/device detection | IoT-only; cannot process unstructured CTI reports; alert-only, no mitigation | https://ieeexplore.ieee.org/document/11175688 |
| P7 | CANAL: Cyber Activity News Alerting Language Model | Patel, Yeh, Gondhalekar | 2024 | IEEE ICAIC | Original Research | Fine-tuned BERT for cyber threat classification from news articles | Binary alert output only; no TTP mapping, no enrichment, no mitigation | https://ieeexplore.ieee.org/document/10473567 |
| P8 | A Temporal Convolutional Network-based Approach for Network Intrusion Detection | Nazre, Budke, Oak et al. | 2024 | IEEE ICIICS | Original Research | TCN model on Edge-IIoTset achieving 96.72% detection accuracy | Pure detection; no threat context enrichment or actionable response step | https://ieeexplore.ieee.org/document/10602395 |
| P9 | Explainable AI for Comparative Analysis of Intrusion Detection Models | Corea, Liu, Wang, Niu, Song | 2024 | IEEE MeditCom | Original Research | XAI applied to multiple classifiers on UNSW-NB15 dataset | XAI explains classifier output only; no pipeline to mitigation recommendation | https://ieeexplore.ieee.org/document/10734105 |
| P10 | RHINO: Guided Reasoning for Mapping Network Logs to MITRE ATT&CK Using LLMs | Meng, Gui, Li, Wu | 2025 | arXiv cs.CR | Original Research | Three-phase LLM framework: log → narrative → MITRE technique (86-88% accuracy) | Maps to MITRE only; no enrichment of IOCs/CVEs; no mitigation output stage | https://arxiv.org/abs/2504.01252 |
| P11 | Rule-ATT&CK Mapper (RAM): Mapping SIEM Rules to TTPs Using LLMs | Wudali, Kravchik, Malul, Gandhi et al. | 2025 | arXiv cs.CR | Original Research | Multi-stage LLM pipeline mapping SIEM detection rules to MITRE ATT&CK | Covers rule-to-TTP mapping only; no threat ingestion, enrichment, or response | https://arxiv.org/abs/2502.04262 |
| P12 | DroidTTP: Mapping Android Applications with TTP for CTI | Arikkat, Vinod, Rehiman, Nicolazzo et al. | 2025 | arXiv cs.CR | Original Research | RAG + LLM for MITRE TTP classification of Android malware with 0.95+ Jaccard score | Android-specific; no multi-source CTI input; no mitigation or analyst output | https://arxiv.org/abs/2504.10742 |
| P13 | XG-NID: Dual-Modality Network Intrusion Detection Using GNN and LLM | Farrukh, Wali, Khan, Bastian | 2024 | arXiv cs.CR | Original Research | GNN + LLM dual-modality IDS with human-readable explanation and 97% F1 score | Detection and explanation only; no CTI enrichment pipeline or mitigation stage | https://arxiv.org/abs/2408.16208 |
| P14 | Tri-LLM Cooperative Federated Zero-Shot Intrusion Detection | Jamshidi, Abdul Wahab, Khomh, Nafi | 2026 | arXiv cs.CR | Original Research | Three LLMs (GPT-4o, DeepSeek, LLaMA) in federated IDS detecting zero-day attacks | Federated IDS only; no CTI context enrichment, no MITRE mapping, no mitigation | https://arxiv.org/abs/2501.12060 |
| P15 | CyberLLM-FINDS: Instruction-Tuned LLMs with RAG and Graph for MITRE Evaluation | Iyer, Bobadilla, Iyengar | 2026 | arXiv cs.CR | Original Research | Fine-tuned Gemma-2B with RAG + graph for MITRE ATT&CK TTP coverage | MITRE alignment only; no IOC/CVE extraction, no enrichment→mitigation pipeline | https://arxiv.org/abs/2504.10464 |
| P16 | Hierarchical RAG for Adversarial Technique Annotation in CTI Text (H-TechniqueRAG) | Morbiato, Keller, Nair, Romano | 2026 | arXiv cs.CR | Original Research | Two-stage hierarchical RAG: tactic first → technique, reduces search space by 77.5% | Annotation only; no enrichment of IOCs or CVEs; no downstream mitigation stage | https://arxiv.org/abs/2503.02382 |
| P17 | From IOCs to Regex: Automating CTI Operationalization for SOC with LLMs | Tseng, Zhang, Yeh, Sun et al. | 2026 | arXiv cs.CR | Original Research | LLM converts CTI IOCs to detection regex with 99.1% hit rate and 0.8% FPR | IOC operationalization only; no threat enrichment or mitigation recommendation | https://arxiv.org/abs/2501.10433 |
| P18 | MobiLLM: Agentic AI for Closed-Loop Threat Mitigation in 6G Open RANs | Sharma, Wen, Yegneswaran et al. | 2025 | arXiv cs.CR | Original Research | Multi-agent LLM system: threat analysis → RAG classification → automated response in 6G | 6G/RAN-specific; uses MITRE FiGHT only; not generalizable to multi-domain CTI | https://arxiv.org/abs/2503.04397 |
| P19 | CTI Echo Chamber: 20 Years of Cyber Threat Reporting Analysis | Suarez-Roman, Marciori, Conti, Tapiador | 2026 | arXiv cs.CR | Original Research | LLM pipeline analysing 13,308 CTI reports over 20 years — extracts actors, IOCs, TTPs | Shows CTI fragmentation problem; confirms multi-source CTI fusion is unsolved | https://arxiv.org/abs/2503.07920 |
| P20 | Evaluating Language Models for Threat Detection in IoT Security Logs | Tejero-Fernández, Sánchez-Macián | 2025 | arXiv cs.CR | Original Research | LLM fine-tuning (zero-shot/few-shot) for IoT log anomaly detection + CAPEC mitigation hints | IoT-only; CAPEC mapping is basic; no chain-of-thought mitigation with D3FEND codes | https://arxiv.org/abs/2501.05004 |

---

## PART 2 — Other Open-Access Papers (10 Papers)

| # | Title | Authors | Year | Venue | Type | What It Does | Gap for Our Project | Link |
|---|-------|---------|------|-------|------|-------------|--------------------|----|
| O1 | CyberRAG: An Agentic RAG Cyber Attack Classification and Reporting Tool | Blefari, Cosentino, Pironti, Furfaro, Marozzo | 2026 | Future Generation Computer Systems (Elsevier) | Original Research | Agentic RAG system classifying SQL Injection, XSS, SSTI with 94.92% accuracy + LLM explanations | Covers detection + classification only; no CTI ingestion pipeline, no MITRE mitigation output | https://doi.org/10.1016/j.future.2025.107842 |
| O2 | AutoMalDesc: Large-Scale Script Analysis for Cyber Threat Research | Apostu, Preda, Damir et al. | 2026 | AAAI 2026 | Original Research | Automated NL explanations for malware script detections using iterative self-paced learning | Script analysis only; no multi-source CTI input; no MITRE ATT&CK mapping or mitigation pipeline | https://arxiv.org/abs/2412.18364 |
| O3 | Towards Effective Identification of Attack Techniques in CTI Reports Using LLMs | Nguyen, Tariq, Baruwal Chhetri, Vo | 2025 | WWW'25 | Original Research | LLM + SciBERT for TTP extraction from CTI reports with F1 > 0.90 on several techniques | TTP extraction only; no full pipeline from CTI to enriched event to mitigation | https://arxiv.org/abs/2502.01819 |
| O4 | AthenaBench: Dynamic Benchmark for Evaluating LLMs in CTI | Alam, Bhusal, Ahmad, Rastogi, Worth | 2026 | arXiv cs.CR (v2) | Original Research | Benchmarks 12 LLMs including GPT-5 and Gemini-2.5 Pro on CTI tasks including mitigation planning | Confirms even frontier LLMs underperform on mitigation planning — validates our RAG+CoT approach | https://arxiv.org/abs/2504.12560 |
| O5 | CTIArena: Benchmarking LLM Knowledge Across Heterogeneous CTI | Cheng, Liu, Li, Song, Gao | 2025 | arXiv cs.CR | Original Research | Evaluates 10 LLMs on 9 CTI tasks spanning structured feeds, reports, and raw logs | Most LLMs fail on multi-source CTI without domain RAG — exactly what our project addresses | https://arxiv.org/pdf/2510.11974 |
| O6 | FALCON: Autonomous CTI Mining with LLMs for IDS Rule Generation | Mitra, Bazarov, Duclos, Mittal et al. | 2025 | arXiv cs.CR | Original Research | Autonomous pipeline extracting CTI text and generating Snort + YARA rules using LLMs | Detection rules only; no human-readable mitigation, no D3FEND codes, no explainability | https://arxiv.org/pdf/2508.18684 |
| O7 | CTISum: Benchmark Dataset for Cyber Threat Intelligence Summarization | Peng, Ding, Wang, Cui et al. | 2024 | arXiv cs.CL | Original Research | Benchmark for LLM-based CTI report summarization with multi-stage annotation pipeline | LLMs still struggle with CTI summarization — supports need for domain-specific RAG augmentation | https://arxiv.org/abs/2412.06614 |
| O8 | XGen-Q: Explainable Domain-Adaptive LLM with RAG for Software Security | Jelodar, Meymani, Razavi-Far, Ghorbani | 2025 | arXiv cs.IR | Original Research | RAG + LLM for malware analysis on 1M+ samples with forensic reporting and obfuscation handling | Malware analysis only; no CTI ingestion pipeline or end-to-end response recommendation | https://arxiv.org/abs/2504.05819 |
| O9 | Generative AI in Cybersecurity: Comprehensive Review of LLM Applications | Ferrag, Alwahedi, Battah et al. | 2024 | arXiv cs.CR | Survey | Review of 42 LLMs across IDS, malware, CVE, RAG technique evaluation | Identifies absence of unified RAG pipeline linking CTI ingestion, enrichment, and mitigation | https://arxiv.org/pdf/2405.12750 |
| O10 | Large Language Models for Security Operations Centers: A Comprehensive Survey | Habibzadeh, Feyzi, Ebrahimi Atani | 2025 | arXiv cs.CR | Survey | First comprehensive survey of LLM applications in SOC workflows — alert triage, threat hunting, IR | Confirms no production-ready end-to-end LLM SOC pipeline exists — validates our project objective | https://arxiv.org/abs/2503.02910 |

---

## Citation Quick Reference — Which Paper Supports Which Objective

| Project Objective | Supporting Papers |
|---|---|
| O1 — CTI Ingestion + MITRE RAG Enrichment | P2, P5, P10, P11, P12, P15, P16, P17, O3, O7, O9 |
| O2 — LLM Threat Classification | P1, P4, P7, P8, P9, P13, P14, O1, O2 |
| O3 — Explainable Mitigation Recommendation | P3, P4, P6, P18, P20, O4, O5, O6, O10 |
| O4 — System Evaluation and Benchmarking | P2, P7, P9, O4, O5, O7 |

---

## 4 Project Objectives

| # | Objective | Description | Gap Addressed |
|---|-----------|-------------|--------------|
| **O1** | Context-Aware Threat Ingestion Pipeline | Ingest multi-source CTI (logs, OSINT feeds, CVE/NVD data) and enrich each threat event with MITRE ATT&CK TTP mappings using RAG over the ATT&CK knowledge base | Gaps in O5 (CTIArena), O9 (Ferrag et al.) |
| **O2** | LLM-Powered Threat Classification Module | Classify threats by type, severity level, attack stage, and affected asset category using LLM contextual reasoning — not static signature matching | Gaps in P2 (Hasanov et al.), P5 (Elouardi et al.), P20 (Tejero-Fernández) |
| **O3** | Explainable Mitigation Recommendation Engine | Generate context-specific, ranked mitigation recommendations with chain-of-thought justification aligned to MITRE D3FEND and NIST CSF frameworks | Gaps in P1 (Hmimou et al.), P4 (Melhem et al.), O6 (FALCON) |
| **O4** | System Evaluation and Benchmarking | Evaluate performance against real CTI datasets and MITRE ATT&CK evaluations; measure enrichment quality, classification accuracy, and mitigation relevance score | Gaps in O4 (AthenaBench), O5 (CTIArena) |

---

## How to Cite in Report (IEEE Format)

- IEEE Access papers: [P1] A. Hmimou, M. Tabaa, A. Khiat, and Z. Hidila, "A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models," *IEEE Access*, 2025.
- arXiv papers: [P10] X. Meng, G. Gui, J. Li, and H. Wu, "RHINO: Guided Reasoning for Mapping Network Logs to MITRE ATT&CK Using LLMs," *arXiv preprint arXiv:2504.01252*, 2025.
- Elsevier paper: [O1] M. Blefari et al., "CyberRAG: An Agentic RAG Cyber Attack Classification and Reporting Tool," *Future Generation Computer Systems*, Elsevier, 2026.

---

*File: CITATIONS_REFERENCE.md | Project: Context-Aware Cyber Threat Analytics and Mitigation Recommendation using LLMs | Date: 2026-05-20*
