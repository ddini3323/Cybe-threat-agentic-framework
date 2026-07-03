"""
Generates the complete 60-page college project report as a Word (.docx) file.
Run:  python generate_report.py
Output: CTI_Project_Report.docx
Requires: pip install python-docx
Diagrams folder must exist (run generate_diagrams.py first).
"""

from docx import Document
from docx.shared import Pt, Inches, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import os

doc = Document()

DIAGRAM_DIR = "diagrams"

# ── page margins ──────────────────────────────────────────────────────────────
for section in doc.sections:
    section.top_margin    = Cm(2.5)
    section.bottom_margin = Cm(2.5)
    section.left_margin   = Cm(3.0)
    section.right_margin  = Cm(2.5)

# ── styles helper ─────────────────────────────────────────────────────────────
def set_font(run, size=12, bold=False, color=None):
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.name = "Times New Roman"
    if color:
        run.font.color.rgb = RGBColor(*color)

def heading(text, level=1):
    p = doc.add_heading(text, level=level)
    for run in p.runs:
        run.font.name = "Times New Roman"
        run.font.color.rgb = RGBColor(0, 0, 0)
    return p

def para(text, align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=12, bold=False, indent=False):
    p = doc.add_paragraph()
    p.alignment = align
    if indent:
        p.paragraph_format.first_line_indent = Inches(0.5)
    run = p.add_run(text)
    set_font(run, size=size, bold=bold)
    p.paragraph_format.space_after  = Pt(6)
    p.paragraph_format.space_before = Pt(0)
    return p

def fig(path, caption, width=5.5):
    if os.path.exists(path):
        doc.add_picture(path, width=Inches(width))
        last = doc.paragraphs[-1]
        last.alignment = WD_ALIGN_PARAGRAPH.CENTER
    else:
        p = doc.add_paragraph(f"[Figure: {os.path.basename(path)} not found — run generate_diagrams.py first]")
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cap = doc.add_paragraph(caption)
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    for run in cap.runs:
        run.font.name  = "Times New Roman"
        run.font.size  = Pt(10)
        run.font.bold  = True
        run.font.italic = True

def table(headers, rows, caption=""):
    if caption:
        cp = doc.add_paragraph(caption)
        cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for run in cp.runs:
            run.font.bold   = True
            run.font.name   = "Times New Roman"
            run.font.size   = Pt(11)
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_row = t.rows[0].cells
    for i, h in enumerate(headers):
        hdr_row[i].text = h
        for para_ in hdr_row[i].paragraphs:
            for run in para_.runs:
                run.font.bold = True
                run.font.name = "Times New Roman"
                run.font.size = Pt(10)
    for row_data in rows:
        row = t.add_row().cells
        for i, val in enumerate(row_data):
            row[i].text = str(val)
            for para_ in row[i].paragraphs:
                for run in para_.runs:
                    run.font.name = "Times New Roman"
                    run.font.size = Pt(9)
    doc.add_paragraph()

def pb():
    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════════════
# TITLE PAGE
# ══════════════════════════════════════════════════════════════════════════════
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = p.add_run("RV COLLEGE OF ENGINEERING, BENGALURU – 560059")
set_font(run, 14, bold=True)

para("Department of Information Science and Engineering",
     align=WD_ALIGN_PARAGRAPH.CENTER, size=13, bold=True)
doc.add_paragraph()
doc.add_paragraph()

para("PROJECT REPORT", align=WD_ALIGN_PARAGRAPH.CENTER, size=16, bold=True)
doc.add_paragraph()
para("On", align=WD_ALIGN_PARAGRAPH.CENTER, size=13)
doc.add_paragraph()

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = p.add_run("Context-Aware Cyber Threat Analytics and Mitigation\nRecommendation Using Large Language Models")
set_font(run, 15, bold=True)

doc.add_paragraph()
doc.add_paragraph()
para("Submitted in partial fulfillment of the requirements for the degree of",
     align=WD_ALIGN_PARAGRAPH.CENTER, size=12)
para("Master of Technology in Information Technology",
     align=WD_ALIGN_PARAGRAPH.CENTER, size=13, bold=True)
doc.add_paragraph()

para("Submitted by", align=WD_ALIGN_PARAGRAPH.CENTER, size=12)
para("Dinesh Kumar S  (USN: [Your USN])",
     align=WD_ALIGN_PARAGRAPH.CENTER, size=13, bold=True)
doc.add_paragraph()

para("Under the guidance of", align=WD_ALIGN_PARAGRAPH.CENTER, size=12)
para("Dr. Ashwini K B\nAssociate Professor\nDepartment of Information Science and Engineering",
     align=WD_ALIGN_PARAGRAPH.CENTER, size=13, bold=True)
doc.add_paragraph()
doc.add_paragraph()
para("Academic Year 2025–2026", align=WD_ALIGN_PARAGRAPH.CENTER, size=12, bold=True)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# ABSTRACT
# ══════════════════════════════════════════════════════════════════════════════
heading("Abstract", 1)
para(
    "Modern cyber threat intelligence workflows increasingly relied on analysing large volumes of "
    "unstructured information obtained from social media, threat feeds, reports, and open-source "
    "intelligence sources. Manual threat analysis was time-consuming, contextual information was "
    "often lost, and mitigation recommendations were difficult to generate consistently. To address "
    "these challenges, this project proposed a context-aware cyber threat analytics system using "
    "local Large Language Models (LLMs) to automate threat analytics and mitigation support. The "
    "system combined a multi-agent pipeline with Retrieval-Augmented Generation (RAG) and the MITRE "
    "Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) framework to enrich raw threat "
    "data with relevant security context, extract Indicators of Compromise (IOCs), Tactics, "
    "Techniques, and Procedures (TTPs), Common Vulnerabilities and Exposures (CVEs), and attack "
    "vectors, and generate actionable mitigation recommendations.", indent=True)
para(
    "The proposed system was designed with five main agents: ingestion, enrichment, pattern "
    "discovery, mitigation, and validation. Threat data collected from live feeds and manual inputs "
    "was normalised into a structured schema and then processed through a local LLM-based enrichment "
    "stage. Relevant contextual knowledge was retrieved from a local vector database containing MITRE "
    "ATT&CK mappings, which helped the model produce more accurate and grounded analysis. The pattern "
    "discovery module grouped similar threat events based on weighted Jaccard similarity, while the "
    "mitigation module generated defensive actions mapped to MITRE D3FEND countermeasures. A "
    "validation layer checked the safety and practicality of generated mitigations before presentation "
    "to the analyst.", indent=True)
para(
    "The outcome of this project was a privacy-preserving and analyst-friendly CTI platform that "
    "supported faster threat interpretation, improved situational awareness, and provided more "
    "reliable response recommendations. By keeping all processing local and using RAG for contextual "
    "grounding, the system reduced reliance on cloud-based APIs while improving adaptability to "
    "changing threats.", indent=True)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 1 — INTRODUCTION
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 1: Introduction", 1)

heading("1.1  Background", 2)
para(
    "The global cybersecurity landscape has undergone a dramatic transformation over the past decade. "
    "Nation-state actors, organised criminal groups, and opportunistic attackers continuously probe "
    "enterprise networks, critical infrastructure, and government systems using increasingly "
    "sophisticated methods. According to industry reports, the average organisation receives hundreds "
    "of thousands of security alerts per day, the vast majority of which require skilled human "
    "analysis to triage effectively. Security Operations Centres (SOCs) are the primary line of "
    "defence against these threats, yet analysts are overwhelmed by the sheer volume of raw "
    "telemetry. Cyber Threat Intelligence (CTI) has emerged as a discipline dedicated to converting "
    "raw security data into contextualised, actionable knowledge that supports faster and more "
    "accurate decision-making.", indent=True)
para(
    "Traditional CTI workflows are heavily manual. An analyst must collect threat data from disparate "
    "sources such as Indicators of Compromise (IOCs) shared via email, threat reports in PDF format, "
    "live feeds from platforms like Mastodon and URLhaus, and vendor advisories. Each piece of "
    "intelligence must be cross-referenced against known attack frameworks, enriched with contextual "
    "background, and translated into a defensive action. This process is not only time-intensive but "
    "also error-prone, as critical context is frequently lost when intelligence crosses organisational "
    "boundaries or is handled by analysts with varying levels of expertise.", indent=True)
para(
    "The advent of Large Language Models (LLMs) presents a compelling opportunity to automate "
    "significant portions of the CTI workflow. LLMs have demonstrated an ability to parse "
    "unstructured text, extract structured entities, reason over domain-specific knowledge, and "
    "generate coherent natural-language summaries. However, raw LLMs applied to cybersecurity tasks "
    "without domain grounding tend to hallucinate — that is, they fabricate plausible-sounding but "
    "incorrect technical identifiers such as non-existent MITRE ATT&CK technique IDs or CVE numbers. "
    "This is a critical failure mode in a security context where a false recommendation may direct "
    "analyst attention to a non-existent threat.", indent=True)

heading("1.2  Motivation", 2)
para(
    "The motivation for this project arose from the convergence of three observations. First, "
    "existing CTI automation tools address isolated sub-tasks: some tools extract IOCs, others map "
    "TTPs, and a few generate alerts, but no single locally-deployable system automates the complete "
    "chain from raw input to validated mitigation. Second, the most capable LLM systems require "
    "cloud API access, which is incompatible with the data-handling policies of classified, "
    "air-gapped, or privacy-regulated SOC environments. Third, Retrieval-Augmented Generation (RAG) "
    "has proven effective at grounding LLM outputs in verified knowledge bases, suppressing "
    "hallucinations while maintaining the model's natural-language generation capability.", indent=True)
para(
    "Together, these observations motivated the design of a system that: (a) automates the full "
    "CTI pipeline end-to-end; (b) operates entirely on local hardware without cloud dependencies; "
    "and (c) grounds all LLM calls in a verified MITRE ATT&CK knowledge base through RAG, "
    "eliminating hallucinated identifiers while producing actionable, explainable mitigations.", indent=True)

heading("1.3  Problem Statement", 2)
para(
    "Security analysts in operational SOC environments receive threat data from heterogeneous "
    "sources — network logs, threat feeds, vulnerability advisories, and social-media intelligence "
    "— in formats that resist automated processing. The core challenge is not data availability "
    "but structured interpretation: converting unstructured, multi-source threat text into "
    "actionable, verified defensive recommendations without human intervention at each stage.", indent=True)
para(
    "Three specific sub-problems remain unsolved. First, no existing system performs the complete "
    "ingestion-to-mitigation chain in a single locally-deployable pipeline. Second, LLMs applied "
    "to CTI tasks without domain grounding hallucinate MITRE technique identifiers and CVE numbers. "
    "Third, all existing end-to-end proposals depend on cloud-hosted LLMs or external APIs, which "
    "are prohibited in privacy-constrained SOC environments.", indent=True)

heading("1.4  Objectives", 2)
objectives = [
    "To design and implement a five-agent CTI pipeline that automates ingestion, enrichment, pattern discovery, mitigation generation, and validation end-to-end.",
    "To ground all LLM enrichment calls in a locally indexed 691-technique MITRE ATT&CK v18.1 knowledge base using RAG, eliminating hallucinated technique identifiers.",
    "To implement a weighted Jaccard similarity-based pattern discovery mechanism that clusters threat events by TTP overlap, malware family, and attack vector.",
    "To generate MITRE D3FEND-mapped, chain-of-thought mitigation recommendations with deterministic safety validation before analyst presentation.",
    "To develop a reproducible five-metric benchmark framework (EvaluatorAgent) for systematic pipeline quality tracking.",
    "To deploy the entire system on commodity CPU hardware without cloud services, external APIs, or GPU requirements.",
]
for i, obj in enumerate(objectives, 1):
    p = doc.add_paragraph(style="List Number")
    run = p.add_run(obj)
    set_font(run, 11)

heading("1.5  Scope of the Project", 2)
para(
    "The scope of this project covers the design, implementation, and evaluation of a locally "
    "deployable CTI automation system. The system accepts threat input in four formats: free text, "
    "JSON, CSV, and live social-media feeds. It performs automated enrichment, classification, "
    "pattern clustering, mitigation generation, and safety validation. The system is evaluated on "
    "a 20-event test corpus spanning four threat categories. The scope does not extend to "
    "real-time network packet inspection, hardware sensor integration, or commercial SIEM "
    "integration, which are identified as future work directions.", indent=True)

heading("1.6  Organisation of the Report", 2)
para(
    "The remainder of this report is organised as follows. Chapter 2 presents a review of "
    "relevant literature. Chapter 3 describes the system analysis including requirements and "
    "use case modelling. Chapter 4 presents the system design including architecture, data flow, "
    "and entity-relationship diagrams. Chapter 5 covers implementation details including "
    "technology choices and key challenges. Chapter 6 describes the testing methodology and "
    "results. Chapter 7 presents experimental results and analysis. Chapter 8 concludes the "
    "report and outlines future work. Chapter 9 lists all references.", indent=True)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 2 — LITERATURE REVIEW
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 2: Literature Review", 1)
para(
    "This chapter reviews existing work in the areas of LLM-based threat detection and "
    "classification, AI-driven intrusion detection, threat modelling, and CTI pipeline "
    "automation. The review is restricted to open-access IEEE publications from 2022 onwards "
    "that are directly relevant to the problem addressed in this project.", indent=True)

heading("2.1  LLM-Based Threat Detection and Multi-Agent Systems", 2)
para(
    "Hmimou et al. [1] proposed a multi-agent LLM system for cybersecurity threat detection and "
    "correlation, published in IEEE Access (2025). The system employs a threat correlation engine "
    "across multiple agents and demonstrated strong detection performance on benchmark datasets. "
    "However, the system produces no explainable mitigation output and does not integrate MITRE "
    "ATT&CK enrichment, leaving the detection-to-response gap unaddressed. This work directly "
    "motivated the multi-agent architecture adopted in the proposed system.", indent=True)
para(
    "Melhem et al. [2] presented LENS, a lightweight explainable LLM-based Advanced Persistent "
    "Threat (APT) detection system deployed at the network edge for 6G environments, published in "
    "IEEE Access (2025). LENS demonstrates strong APT detection with explainability at the edge "
    "but is constrained to 6G network scenarios and halts at the detection stage without generating "
    "actionable response recommendations. The explainability principles from LENS informed the "
    "chain-of-thought reasoning design in the mitigation agent.", indent=True)
para(
    "Mahmood et al. [3] fine-tuned a large language model on IoT device logs for anomaly detection "
    "and malicious device identification, published in IEEE Access (2025). The system achieves "
    "strong performance on IoT-specific datasets but is limited to IoT environments and outputs "
    "alerts only, with no pathway to structured mitigation. This work confirmed the feasibility "
    "of local LLM fine-tuning for security tasks.", indent=True)
para(
    "Patel et al. [4] fine-tuned BERT for cyber threat classification from open-source news "
    "articles in the CANAL system (IEEE ICAIC, 2024). CANAL classifies news articles into threat "
    "categories with reasonable accuracy but produces binary alert output without TTP extraction "
    "or MITRE mapping. The news-article ingestion concept was adapted in the free-text input "
    "channel of the proposed ingestion agent.", indent=True)

heading("2.2  Intrusion Detection and AI-Driven Analysis", 2)
para(
    "Elouardi et al. [5] conducted a comprehensive survey of hybrid CNN and LLM architectures "
    "for network intrusion detection systems, published in IEEE Access (2024). The survey found "
    "that while deep learning models achieve high accuracy on labelled datasets such as NSL-KDD "
    "and CICIDS, performance degrades significantly on unstructured, free-text threat intelligence. "
    "This finding directly validated the need for the RAG-grounded LLM approach adopted in this "
    "project, as structured dataset performance does not translate to operational CTI scenarios.", indent=True)
para(
    "Corea et al. [6] evaluated explainable AI approaches for comparative analysis of intrusion "
    "detection models (IEEE MeditCom, 2024). The study demonstrated that XAI methods improve "
    "analyst trust but remain limited to structured network-log inputs with no capability for "
    "natural-language threat enrichment. The explainability gap identified by Corea et al. "
    "motivated the inclusion of human-readable reasoning in the mitigation output.", indent=True)
para(
    "Nazre et al. [7] achieved 96.72% detection accuracy using temporal convolutional networks "
    "for network intrusion detection (IEEE ICIICS, 2024). The system excels at packet-level "
    "anomaly detection but provides no threat context, TTP mapping, or mitigation guidance. "
    "The high accuracy of TCN-based detection was noted as a potential integration point for "
    "future work, where packet-level alerts could feed the ingestion agent.", indent=True)

heading("2.3  Threat Modelling, Mitigation, and CTI Surveys", 2)
para(
    "Salek et al. [8] applied LLM combined with MITRE ATT&CK for threat modelling in "
    "transportation Cyber-Physical Systems, published in IEEE Access (2025). The system maps "
    "threats to MITRE techniques within the transportation domain but produces outputs locked "
    "to that specific domain and cannot generalise to multi-source, multi-domain CTI inputs. "
    "The MITRE ATT&CK mapping methodology from this work was adapted and generalised in the "
    "enrichment agent.", indent=True)
para(
    "Hasanov et al. [9] conducted a systematic literature review of LLM applications in "
    "cybersecurity across 73 papers, published in IEEE Access (2024). The review confirmed "
    "that individual sub-tasks such as log analysis, malware classification, and threat "
    "summarisation are well-studied in isolation, but no unified end-to-end pipeline bridging "
    "ingestion, enrichment, and automated response has been deployed in practice. This finding "
    "provided the primary motivation for this project.", indent=True)

heading("2.4  Comparative Summary and Gap Analysis", 2)
para(
    "Table 2.1 summarises the nine reviewed papers, their methodology, and the gaps identified. "
    "The comparison reveals three persistent gaps in the existing literature that are addressed "
    "by the proposed system.", indent=True)
table(
    ["Ref", "Authors", "Year", "Venue", "Focus", "Gap"],
    [
        ["[1]", "Hmimou et al.", "2025", "IEEE Access", "Multi-agent threat detection", "No MITRE enrichment or mitigation"],
        ["[2]", "Melhem et al.", "2025", "IEEE Access", "LLM APT detection (6G)", "6G-specific, no response step"],
        ["[3]", "Mahmood et al.", "2025", "IEEE Access", "LLM IoT anomaly detection", "IoT-specific, alerts only"],
        ["[4]", "Patel et al.", "2024", "IEEE ICAIC", "BERT threat classification", "Binary output, no TTP mapping"],
        ["[5]", "Elouardi et al.", "2024", "IEEE Access", "CNN+LLM IDS survey", "Structured data only"],
        ["[6]", "Corea et al.", "2024", "IEEE MeditCom", "XAI for IDS comparison", "No NL enrichment capability"],
        ["[7]", "Nazre et al.", "2024", "IEEE ICIICS", "TCN intrusion detection", "No context or mitigation"],
        ["[8]", "Salek et al.", "2025", "IEEE Access", "LLM CTI threat modelling", "Domain-locked (transport CPS)"],
        ["[9]", "Hasanov et al.", "2024", "IEEE Access", "LLM cybersecurity survey", "Confirms end-to-end gap"],
    ],
    caption="Table 2.1: Comparative Summary of Reviewed Literature"
)
para(
    "As shown in Table 2.1, no reviewed system addresses the full ingestion-to-mitigation "
    "pipeline in a single locally-deployable system. Every existing approach either targets "
    "a specific domain, stops at detection/classification, or requires cloud API access. "
    "The proposed system directly fills this gap.", indent=True)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 3 — SYSTEM ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 3: System Analysis", 1)
para(
    "This chapter presents the system analysis for the proposed CTI system, including "
    "functional and non-functional requirements, use case modelling, and context-level "
    "data flow analysis.", indent=True)

heading("3.1  Functional Requirements", 2)
func_reqs = [
    ("FR-01", "The system shall accept threat input in free text, JSON, CSV, and live feed formats."),
    ("FR-02", "The system shall normalise all input formats into a unified ThreatEvent schema with event ID, type, severity, indicator, and timestamp."),
    ("FR-03", "The system shall deduplicate events using MD5 hashing to prevent reprocessing of identical threats."),
    ("FR-04", "The system shall enrich each ThreatEvent using a local LLM grounded in the MITRE ATT&CK knowledge base to extract IOCs, TTPs, CVEs, and attack vectors."),
    ("FR-05", "The system shall store enriched events in a local ChromaDB vector store for self-learning retrieval in future enrichments."),
    ("FR-06", "The system shall discover threat patterns by clustering enriched events using a weighted multi-factor similarity algorithm."),
    ("FR-07", "The system shall generate mitigation recommendations for all events with severity level 3 or above."),
    ("FR-08", "The system shall map each mitigation recommendation to MITRE D3FEND countermeasure identifiers."),
    ("FR-09", "The system shall validate all generated mitigations against safety rules before presenting them to analysts."),
    ("FR-10", "The system shall provide a web dashboard for real-time monitoring of pipeline status, enriched events, patterns, and mitigations."),
    ("FR-11", "The system shall allow analysts to approve or reject mitigations through a human-in-the-loop interface."),
    ("FR-12", "The system shall provide a benchmark endpoint that computes five pipeline quality metrics on demand."),
]
table(["ID", "Requirement"], [[r[0], r[1]] for r in func_reqs],
      caption="Table 3.1: Functional Requirements")

heading("3.2  Non-Functional Requirements", 2)
nfunc_reqs = [
    ("NFR-01", "Performance", "Dashboard API responses shall complete within 500 ms under concurrent load."),
    ("NFR-02", "Privacy", "All processing shall execute locally with no data transmitted to external services."),
    ("NFR-03", "Reliability", "The pipeline shall recover from individual LLM timeout failures without crashing."),
    ("NFR-04", "Usability", "The dashboard shall be accessible via a standard web browser with no plugins."),
    ("NFR-05", "Portability", "The system shall run on commodity Intel Core i7 hardware with 16 GB RAM and no GPU."),
    ("NFR-06", "Scalability", "The vector store shall support at least 1000 stored threat events without performance degradation."),
    ("NFR-07", "Security", "Generated mitigations containing dangerous commands shall be automatically rejected."),
]
table(["ID", "Category", "Requirement"], nfunc_reqs,
      caption="Table 3.2: Non-Functional Requirements")

heading("3.3  Use Case Diagram", 2)
para(
    "Figure 3.1 illustrates the use case diagram for the CTI Agentic System. Three external "
    "actors interact with the system. The Security Analyst is the primary user who submits "
    "threats, reviews enriched events and patterns, approves or rejects mitigations, and runs "
    "benchmark evaluations. The System Administrator configures live feed sources and manages "
    "system settings. The Live Feed actor represents automated external sources such as Mastodon "
    "infosec feeds and URLhaus malicious URL feeds that push threat data into the system "
    "automatically.", indent=True)
fig(f"{DIAGRAM_DIR}/01_use_case_diagram.png",
    "Figure 3.1: Use Case Diagram for the CTI Agentic System")
para(
    "As seen in Figure 3.1, the use case 'Submit Threat' is shared between the Security Analyst "
    "and the Live Feed actor, reflecting the dual-mode input capability of the system. The "
    "'Approve / Review Mitigation' use case is exclusive to the Security Analyst, enforcing the "
    "human-in-the-loop requirement. The 'Configure Feeds' and 'Run Benchmark' use cases are "
    "accessible to the System Administrator, who manages the system's operational parameters. "
    "The 'View Dashboard' use case provides a consolidated view of all pipeline outputs and "
    "is the central point of interaction for day-to-day SOC operations.", indent=True)

heading("3.4  Data Flow Diagram — Level 0 (Context Diagram)", 2)
para(
    "Figure 3.2 presents the Level 0 Data Flow Diagram (DFD), also known as the context "
    "diagram. This diagram provides the highest-level view of the system, showing the CTI "
    "Agentic System as a single process interacting with four external entities.", indent=True)
fig(f"{DIAGRAM_DIR}/02_dfd_level0_context.png",
    "Figure 3.2: DFD Level 0 — Context Diagram")
para(
    "As shown in Figure 3.2, the Security Analyst provides threat text or files as input to "
    "the system and receives mitigations and reports as output. The Live Feed (Mastodon/URLhaus) "
    "continuously pushes live CTI feed events into the system. The MITRE ATT&CK Knowledge Base "
    "is queried by the system for TTP and RAG context, and returns technique context to support "
    "enrichment. The SOC Dashboard receives validated mitigations and pipeline reports as output, "
    "and returns analyst approval decisions back to the system. All data flows are internal to "
    "the local network — no external API calls are made.", indent=True)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 4 — SYSTEM DESIGN
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 4: System Design", 1)
para(
    "This chapter presents the detailed system design including the overall architecture, "
    "internal data flow, entity-relationship model, sequence of interactions, and pipeline "
    "activity logic.", indent=True)

heading("4.1  System Architecture Overview", 2)
para(
    "The CTI Agentic System implements a sequential five-agent pipeline with two input "
    "channels and a FastAPI web dashboard. All computation executes on local hardware. "
    "The architecture is designed to be modular, with each agent encapsulated as an "
    "independent Python class that communicates through typed Pydantic v2 schemas. "
    "This design allows individual agents to be updated or replaced without affecting "
    "the rest of the pipeline.", indent=True)
para(
    "The pipeline begins with Agent 1 (Ingestion), which normalises heterogeneous input "
    "into a structured ThreatEvent object. Agent 2 (Enrichment) queries the ChromaDB vector "
    "store for relevant MITRE ATT&CK context before invoking the local LLM, producing an "
    "EnrichedEvent. Enriched events are simultaneously stored back into ChromaDB, forming "
    "a self-learning loop. Agent 3 (Pattern Discovery) clusters enriched events using weighted "
    "Jaccard similarity into ThreatPattern objects. Agent 4 (Mitigation) generates D3FEND-mapped "
    "recommendations using chain-of-thought prompting. Agent 5 (Validation) applies deterministic "
    "safety rules before results are surfaced through the FastAPI dashboard.", indent=True)

heading("4.2  Data Flow Diagram — Level 1", 2)
para(
    "Figure 4.1 presents the Level 1 DFD, which expands the single system process from the "
    "context diagram into five internal processes corresponding to the five agents, along "
    "with two data stores.", indent=True)
fig(f"{DIAGRAM_DIR}/03_dfd_level1.png",
    "Figure 4.1: DFD Level 1 — Internal Pipeline Data Flows")
para(
    "As illustrated in Figure 4.1, the data flow progresses sequentially from top to bottom. "
    "Process P1 (Ingestion and Normalisation) receives raw threat data from the analyst or "
    "live feed and produces a ThreatEvent. Process P2 (LLM Enrichment with RAG) queries "
    "Data Store D1 (ChromaDB containing MITRE ATT&CK knowledge and historical threat reports) "
    "before invoking the LLM, and stores the resulting enriched event back into D1. The dashed "
    "bidirectional arrows between P2 and D1 represent this RAG query-and-store loop. Process "
    "P3 (Pattern Discovery) reads from and writes to Data Store D2 (Pattern Store) to maintain "
    "the current set of known threat patterns. Processes P4 and P5 (Mitigation Generation and "
    "Validation) operate sequentially, with the final validated output flowing to the SOC Dashboard.", indent=True)

heading("4.3  ER / Data Model Diagram", 2)
para(
    "Figure 4.2 presents the Entity-Relationship (ER) diagram showing the four core data "
    "entities and their relationships.", indent=True)
fig(f"{DIAGRAM_DIR}/04_er_data_model.png",
    "Figure 4.2: ER / Data Model Diagram")
para(
    "As shown in Figure 4.2, the data model consists of four entities forming a linear "
    "transformation chain. The ThreatEvent entity serves as the root, capturing the raw "
    "input with fields including event_id (MD5 hash), event_type, severity (1-5 scale), "
    "raw_text, indicator, and timestamp. The 'enriches' relationship connects ThreatEvent "
    "to EnrichedEvent, which extends the root with LLM-extracted fields: ttps[], iocs[], "
    "cves[], malware_family, attack_vector, attack_stage, and enrichment_confidence (0.0-1.0). "
    "The 'clusters into' relationship connects ThreatEvent to ThreatPattern, which groups "
    "multiple events sharing similar TTPs and attack characteristics. Finally, the 'triggers' "
    "relationship connects ThreatPattern to MitigationAction, which stores D3FEND codes, "
    "priority level, action steps, LLM reasoning, and validation status.", indent=True)

table(
    ["Entity", "Key Fields", "Purpose"],
    [
        ["ThreatEvent", "event_id, event_type, severity, raw_text, indicator", "Root input schema normalised by Agent 1"],
        ["EnrichedEvent", "ttps[], iocs[], cves[], enrichment_confidence", "LLM-extracted intelligence from Agent 2"],
        ["ThreatPattern", "pattern_id, event_ids[], primary_ttp, pattern_confidence", "Clustered threat group from Agent 3"],
        ["MitigationAction", "d3fend_codes[], action_steps[], validated, priority", "D3FEND-mapped response from Agents 4 & 5"],
    ],
    caption="Table 4.1: Data Entity Summary"
)

heading("4.4  Sequence Diagram", 2)
para(
    "Figure 4.3 illustrates the sequence of interactions between the system components "
    "when an analyst submits a threat through the instant pipeline endpoint.", indent=True)
fig(f"{DIAGRAM_DIR}/05_sequence_diagram.png",
    "Figure 4.3: Sequence Diagram — Threat Processing Flow")
para(
    "As shown in Figure 4.3, the interaction begins with the Security Analyst sending a "
    "POST request to the FastAPI endpoint /api/ingest/instant with the raw threat text. "
    "FastAPI forwards the raw text to the Ingestion Agent, which normalises it and returns "
    "a ThreatEvent. FastAPI then passes the ThreatEvent to the Enrichment Agent, which "
    "issues an embedding-based query to ChromaDB to retrieve relevant MITRE ATT&CK context. "
    "ChromaDB returns the most similar technique descriptions. The Enrichment Agent constructs "
    "a structured prompt and submits it to the local llama3.2:3b model via Ollama. The LLM "
    "returns a JSON object containing extracted TTPs, IOCs, CVEs, and confidence score. The "
    "Enrichment Agent stores the result back to ChromaDB and returns the EnrichedEvent to "
    "FastAPI. The Pattern Agent clusters the event, the Mitigation Agent generates D3FEND-mapped "
    "recommendations, and the Validation Agent checks safety rules. The final validated result "
    "is returned to the analyst as the API response.", indent=True)

heading("4.5  Activity Diagram / Flowchart", 2)
para(
    "Figure 4.4 presents the activity diagram illustrating the complete pipeline logic "
    "including decision points and alternative paths.", indent=True)
fig(f"{DIAGRAM_DIR}/06_activity_flowchart.png",
    "Figure 4.4: Activity Diagram — Pipeline Decision Logic")
para(
    "As depicted in Figure 4.4, the pipeline begins at the START node when threat input "
    "is received. The first decision point checks whether the event is a duplicate by "
    "comparing its MD5 hash against previously processed events. If a duplicate is detected, "
    "the event is discarded and the pipeline terminates for that input. For new events, Agent 2 "
    "performs LLM enrichment and checks whether the enrichment confidence exceeds 0.3. Events "
    "meeting this threshold are stored back to ChromaDB for future retrieval. All enriched "
    "events then proceed to Agent 3 for pattern discovery. The severity decision point checks "
    "whether the event severity is 3 or above; events below this threshold are logged only "
    "without generating mitigations. High-severity events proceed to Agent 4 for mitigation "
    "generation, then to Agent 5 for validation. The validation decision point checks whether "
    "the mitigation passes all safety rules; failed mitigations are flagged and logged, while "
    "passing mitigations are published to the SOC Dashboard.", indent=True)

heading("4.6  Agent Design Summary", 2)
table(
    ["Agent", "Input", "Output", "Key Algorithm"],
    [
        ["Agent 1: Ingestion", "Raw text / JSON / CSV / Feed", "ThreatEvent", "MD5 dedup, regex type detection, keyword severity"],
        ["Agent 2: Enrichment", "ThreatEvent", "EnrichedEvent", "RAG (HNSW cosine), llama3.2:3b at temp=0.1"],
        ["Agent 3: Pattern Discovery", "EnrichedEvent", "ThreatPattern", "Weighted Jaccard similarity (Eq. 1), threshold 0.7"],
        ["Agent 4: Mitigation", "ThreatPattern", "MitigationAction", "Chain-of-thought prompting, D3FEND mapping"],
        ["Agent 5: Validation", "MitigationAction", "Validated action", "Deterministic safety rules (5 checks)"],
    ],
    caption="Table 4.2: Agent Design Summary"
)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 5 — IMPLEMENTATION
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 5: Implementation", 1)
para(
    "This chapter documents the implementation of the CTI Agentic System, covering "
    "the programming language and platform selection rationale, the code conventions "
    "adopted throughout the project, the key difficulties encountered during development "
    "and the strategies used to resolve them, and the four core algorithms implemented "
    "in the pipeline.", indent=True)

heading("5.1  Programming Language Selection", 2)
para(
    "Python 3.12 was selected as the sole implementation language for three reasons.", indent=True)
table(
    ["Reason", "Detail"],
    [
        ["Ecosystem Compatibility",
         "All required libraries — ChromaDB, sentence-transformers, FastAPI, Pydantic, "
         "and the Ollama SDK — have mature, actively maintained Python packages with no "
         "equivalent in other languages at the same maturity level."],
        ["Asyncio Support",
         "The system requires concurrent execution of the LLM inference pipeline and the "
         "web server. Python's native asyncio provides this without multi-threading complexity, "
         "and FastAPI is ASGI-native."],
        ["Rapid Iteration",
         "Python's dynamic typing and interactive REPL allowed each agent to be developed "
         "and verified independently before pipeline integration, reducing the debug cycle "
         "from hours to minutes per agent."],
    ],
    caption="Table 5.1: Python 3.12 Selection Rationale"
)

heading("5.2  Platform Selection", 2)
para(
    "Three core platform choices were made for the LLM runtime, vector database, and "
    "web framework. Each was evaluated against at least two alternatives.", indent=True)
table(
    ["Component", "Selected", "Alternatives Considered", "Selection Rationale"],
    [
        ["LLM Runtime", "Ollama",
         "LM Studio, llama.cpp direct",
         "Exposes a standardised HTTP API on port 11434 enabling drop-in model swapping. "
         "Manages quantisation automatically; llama3.2:3b uses Q4_K_M quantisation (4-bit), "
         "delivering ~75% of full-precision quality at 25% of memory cost."],
        ["Vector Database", "ChromaDB",
         "Qdrant, Milvus, FAISS",
         "Runs embedded in-process with no external server, includes native "
         "sentence-transformer integration, and persists to disk with zero configuration."],
        ["Web Framework", "FastAPI",
         "Flask, Django",
         "ASGI-native async support, automatic Pydantic model integration, and "
         "auto-generated OpenAPI docs covering all 15 endpoints."],
    ],
    caption="Table 5.2: Platform Selection Comparison"
)

heading("5.3  Code Conventions", 2)

heading("5.3.1  Naming Convention", 3)
para(
    "All identifiers follow a consistent naming scheme documented in Table 5.3.", indent=True)
table(
    ["Element", "Convention", "Example"],
    [
        ["Classes",        "PascalCase",    "IngestionAgent, CTIVectorStore"],
        ["Methods",        "snake_case",    "ingest_from_directory, enrich_batch"],
        ["Constants",      "UPPER_SNAKE",   "OLLAMA_MODEL, SIMILARITY_THRESHOLD"],
        ["Pydantic fields","snake_case",    "raw_text, enrichment_confidence"],
        ["API routes",     "/api/noun/verb","/api/mitigations/{id}/status"],
    ],
    caption="Table 5.3: Naming Convention Summary"
)
para(
    "All agent methods carry full type annotations. LLM response fields use Optional[str] "
    "to handle cases where the model omits a field gracefully, preventing KeyError exceptions "
    "during JSON parsing.", indent=True)

heading("5.3.2  Agent Class Declaration Pattern", 3)
para(
    "All five agent classes follow a consistent four-method pattern:", indent=True)
p = doc.add_paragraph()
run = p.add_run(
    "  __init__()        : receives shared CTISystem state reference\n"
    "  process()         : main synchronous processing method\n"
    "  async_process()   : async wrapper implemented via asyncio.to_thread()\n"
    "  _log()            : appends AgentLogEntry to the internal log list"
)
run.font.name = "Courier New"
run.font.size = Pt(10)
para(
    "This pattern ensures every agent is independently testable via process() "
    "and safely callable from the async FastAPI event loop via async_process().", indent=True)

heading("5.4  Difficulties Encountered and Strategies Used", 2)
para(
    "Five significant implementation challenges were identified and resolved during "
    "development. Table 5.4 summarises each difficulty and the strategy applied.", indent=True)
table(
    ["#", "Difficulty", "Root Cause", "Strategy Applied"],
    [
        ["D1", "LLM JSON Parsing Reliability",
         "llama3.2:3b occasionally wraps JSON in markdown code fences or produces trailing commas.",
         "Three-stage extraction pipeline: (1) direct json.loads(), "
         "(2) regex extraction between ```json...``` markers, "
         "(3) raw object scan for first '{' to last '}'. Handles ~98% of observed output formats."],
        ["D2", "Blocking LLM Calls in Async Context",
         "Ollama's SDK uses synchronous HTTP, which would freeze the FastAPI event loop "
         "for the 45-90 second duration of each LLM call.",
         "All LLM calls are wrapped in asyncio.to_thread(), executing in the default "
         "ThreadPoolExecutor while the event loop remains free."],
        ["D3", "MITRE Index Initialisation Time",
         "Embedding all 691 MITRE techniques into ChromaDB on first run takes 45-90 seconds "
         "due to batch embedding generation.",
         "ChromaDB persists to data/chroma_db/. A collection.count() check in is_ready() "
         "skips re-indexing on all subsequent starts."],
        ["D4", "Feed Interference with User Submissions",
         "Concurrent Mastodon feed polling could inject unrelated events into a processing "
         "cycle during a user's instant submission.",
         "An asyncio.Event (user_submission_event) was added. The /api/ingest/instant endpoint "
         "pauses the FeedStreamer, wakes the processing loop early, and resumes feeds after "
         "the instant pipeline completes."],
        ["D5", "Mastodon HTML Content",
         "Mastodon API returns post content as HTML with anchor tags, line breaks, and "
         "escaped characters, breaking IOC regex patterns.",
         "Python's html.parser strips tags to plain text. A defang reversal function "
         "normalises researcher-obfuscated IOCs (hxxps://, [.], [dot]) before indicator extraction."],
    ],
    caption="Table 5.4: Difficulties Encountered and Strategies Applied"
)

heading("5.5  Key Algorithms", 2)

heading("5.5.1  LLM Prompting Strategy (Enrichment Agent)", 3)
para(
    "The enrichment prompt uses a four-section template submitted to llama3.2:3b at "
    "temperature 0.1 (near-deterministic) for consistent parsing:", indent=True)
p = doc.add_paragraph()
run = p.add_run(
    "  Section 1 - System Role:\n"
    '    "You are a senior SOC analyst. Extract threat intelligence from the\n'
    '     following event. Return ONLY valid JSON."\n\n'
    "  Section 2 - MITRE Context block:\n"
    '    "Relevant MITRE ATT&CK techniques (use these IDs if applicable):\n'
    "     T1059.001 - PowerShell [similarity: 0.619]\n"
    '     T1546.013 - PowerShell Profile [similarity: 0.558] ..."\n\n'
    '  Section 3 - Similar Threats block:\n'
    '    "Similar past threats observed: [event summary 1] [event summary 2]"\n\n'
    "  Section 4 - Event data + Output schema:\n"
    "    Raw event text followed by explicit JSON field definitions with types."
)
run.font.name = "Courier New"
run.font.size = Pt(9)

heading("5.5.2  RAG Retrieval Algorithm", 3)
para(
    "The retrieval algorithm operates in four steps:", indent=True)
p = doc.add_paragraph()
run = p.add_run(
    "  Step 1 — Vectorise query:\n"
    "    vector = all-MiniLM-L6-v2.encode(threat_text)   # 384-dim float32\n\n"
    "  Step 2 — HNSW approximate nearest-neighbour search in ChromaDB:\n"
    "    results = collection.query(query_texts=[text], n_results=5,\n"
    '                include=["documents", "metadatas", "distances"])\n\n'
    "  Step 3 — Similarity filtering (ChromaDB returns L2 distances):\n"
    "    cosine_sim = 1 - distance\n"
    "    keep only results where cosine_sim >= 0.35\n\n"
    "  Step 4 — Context string construction:\n"
    "    For each retained result:\n"
    '      context += f"{id} - {name}: {description[:200]}\\n"'
)
run.font.name = "Courier New"
run.font.size = Pt(9)

heading("5.5.3  Jaccard Similarity Clustering", 3)
para(
    "For each pair of EnrichedEvents (A, B), the weighted similarity score is computed "
    "as follows:", indent=True)
p = doc.add_paragraph()
run = p.add_run(
    "  ttp_a, ttp_b = set(A.ttps), set(B.ttps)\n"
    "  if ttp_a or ttp_b:\n"
    "      ttp_j = len(ttp_a & ttp_b) / len(ttp_a | ttp_b)\n"
    "  else:\n"
    "      ttp_j = 0.0\n\n"
    "  malware_bonus = 0.3 if A.malware_family == B.malware_family else 0.0\n"
    "  vector_bonus  = 0.2 if A.attack_vector  == B.attack_vector  else 0.0\n\n"
    "  asset_a, asset_b = set(A.affected_assets), set(B.affected_assets)\n"
    "  asset_j = (len(asset_a & asset_b) / len(asset_a | asset_b)\n"
    "             if (asset_a | asset_b) else 0.0)\n\n"
    "  similarity = ttp_j * 0.4 + malware_bonus + vector_bonus + asset_j * 0.1\n\n"
    "  if similarity >= 0.7:\n"
    "      assign_to_same_pattern(A, B)"
)
run.font.name = "Courier New"
run.font.size = Pt(9)

heading("5.5.4  Threat Type Detection", 3)
para(
    "Threat type is evaluated in priority order across seven categories:", indent=True)
table(
    ["Priority", "Type", "Detection Rule"],
    [
        ["1", "IP",      "Regex ^(\\d{1,3}\\.){3}\\d{1,3}$, each octet 0-255"],
        ["2", "HASH",    "Length in {32, 40, 64} and all hexadecimal characters (MD5 / SHA1 / SHA256)"],
        ["3", "URL",     "Starts with http://, https://, or ftp://"],
        ["4", "CVE",     "Starts with 'CVE-' (case-insensitive)"],
        ["5", "EMAIL",   "Contains '@' and a dot in the domain part"],
        ["6", "DOMAIN",  "Contains '.' and no whitespace"],
        ["7", "UNKNOWN", "None of the above rules matched"],
    ],
    caption="Table 5.5: Threat Type Detection Priority Rules"
)

heading("5.6  Summary", 2)
para(
    "Python 3.12 with FastAPI, ChromaDB, and Ollama forms the core technology stack. "
    "Five implementation challenges — LLM output parsing, async blocking, ChromaDB "
    "initialisation, feed interference, and Mastodon HTML content — were each resolved "
    "through targeted, minimal strategies. The four core algorithms (LLM prompting, "
    "RAG retrieval, Jaccard clustering, and type detection) are deterministic, "
    "explainable, and computationally efficient on commodity hardware.", indent=True)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 6 — SOFTWARE TESTING
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 6: Software Testing", 1)
para(
    "This chapter documents all test cases executed against the CTI Agentic System, "
    "covering per-agent unit tests, REST API endpoint testing, live feed streaming tests, "
    "and performance benchmarks. All tests were executed on the system running locally "
    "on an Intel Core i7 CPU with 16 GB RAM and no GPU.", indent=True)

heading("6.1  Pipeline Agent Testing", 2)

heading("6.1.1  Ingestion Agent Tests", 3)
table(
    ["Test ID", "Input", "Expected Result", "Actual Result", "Status"],
    [
        ["T1.1", "sample_cti_feed.csv (10 rows: IPs, URLs, hashes, CVEs)",
         "10 ThreatEvent objects with correctly detected types",
         "IP: 3, URL: 3, HASH: 2, CVE: 2", "PASS"],
        ["T1.2", "sample_security_events.json (5 events)",
         "5 ThreatEvent objects with populated raw_text",
         "5 ThreatEvent objects created", "PASS"],
        ["T1.3", "Same CSV file submitted twice in succession",
         "Second submission produces 0 new events",
         "processed_files set correctly blocked re-ingestion", "PASS"],
        ["T1.4", 'Raw text: "critical ransomware attack detected"',
         "SeverityLevel.CRITICAL (5)",
         "CRITICAL severity assigned correctly", "PASS"],
    ],
    caption="Table 6.1: Ingestion Agent Test Results"
)

heading("6.1.2  Enrichment Agent Tests", 3)
table(
    ["Test ID", "Input / Pre-condition", "Expected Result", "Actual Result", "Status"],
    [
        ["T2.1", "Ollama running with llama3.2:3b pulled",
         "LLMWrapper.is_available() returns True",
         "True returned", "PASS"],
        ["T2.2", '"PowerShell malware execution fileless attack"',
         "T1059.001 returned with similarity >= 0.5",
         "similarity = 0.619", "PASS"],
        ["T2.3", '"APT group using PowerShell to drop ransomware via phishing email"',
         "EnrichedEvent with ttps[], malware_family, attack_vector populated",
         "ttps: [T1059.001, T1566.001], malware_family: ransomware, attack_vector: phishing",
         "PASS"],
        ["T2.4", "LLM response with markdown code fence wrapping JSON",
         "JSON successfully extracted via stage-2 regex",
         "Extraction successful", "PASS"],
    ],
    caption="Table 6.2: Enrichment Agent Test Results"
)

heading("6.1.3  Pattern Discovery Tests", 3)
table(
    ["Test ID", "Input", "Expected Result", "Actual Result", "Status"],
    [
        ["T3.1", "3 events each with TTPs {T1059.001, T1055}",
         "All 3 grouped into one ThreatPattern (Jaccard = 1.0)",
         "Single pattern with 3 member events", "PASS"],
        ["T3.2", "Event A: {T1059.001, T1055, T1021}; Event B: {T1078, T1136, T1003}",
         "Two separate patterns (Jaccard = 0.0)",
         "Two separate patterns created", "PASS"],
        ["T3.3", "Pattern with 5 member events",
         "confidence = min(0.5 + 5*0.1, 0.95) = 0.95",
         "0.95", "PASS"],
    ],
    caption="Table 6.3: Pattern Discovery Test Results"
)

heading("6.1.4  Mitigation and Validation Tests", 3)
table(
    ["Test ID", "Input", "Expected Result", "Actual Result", "Status"],
    [
        ["T4.1", "EnrichedEvent with severity = CRITICAL (5)",
         "MitigationAction generated (threshold: severity >= 3)",
         "MitigationAction created", "PASS"],
        ["T4.2", "Full enrichment output",
         "All fields populated: title, description, steps (>= 2), sample_rule, reasoning, mitre_d3fend (>= 1), priority",
         "All required fields present", "PASS"],
        ["T5.1", 'MitigationAction step containing "rm -rf /var/log"',
         "validated = False",
         "validated = False, reason logged", "PASS"],
        ["T5.2", '"Block IP 192.168.1.100 on port 443"',
         "validated = True",
         "validated = True", "PASS"],
    ],
    caption="Table 6.4: Mitigation and Validation Test Results"
)

heading("6.2  API Endpoint Testing", 2)
para(
    "All 15 REST endpoints were tested using PowerShell Invoke-RestMethod scripts "
    "(test_endpoints.ps1). Table 6.5 shows the five primary endpoint tests.", indent=True)
table(
    ["Test ID", "Endpoint", "Input", "Expected Result", "Actual Result", "Status"],
    [
        ["T6.1", "POST /api/ingest/json",
         '{"source": "test", "raw_text": "malware detected", ...}',
         'HTTP 200, {"status": "accepted", "event_id": "<id>"}',
         "HTTP 200, event_id returned", "PASS"],
        ["T6.2", "POST /api/ingest/text",
         '"Suspicious IP 10.0.0.1 scanning port 22"',
         "ThreatEvent created with ThreatType.IP",
         "ThreatType.IP assigned", "PASS"],
        ["T6.3", "GET /api/stats",
         "No body",
         "JSON with total_events, events_by_severity, events_by_type",
         "All fields present", "PASS"],
        ["T6.4", "POST /api/mitigations/{id}/status",
         '{"status": "approved"}',
         "Mitigation status updated in app state",
         "Status updated to APPROVED", "PASS"],
        ["T6.5", "POST /api/pipeline/start and /stop",
         "No body",
         "Running flag toggled; confirmed via subsequent /api/stats",
         "Flag toggled correctly", "PASS"],
    ],
    caption="Table 6.5: API Endpoint Test Results"
)

heading("6.3  Feed Streaming Tests", 2)
table(
    ["Test ID", "Test", "Expected Result", "Actual Result", "Status"],
    [
        ["T7.1", "Live GET to infosec.exchange/api/v1/timelines/public",
         "At least 1 post retrieved and normalised as ThreatEvent",
         "Posts retrieved (live feed availability dependent)", "PASS"],
        ["T7.2", "Submit via /api/ingest/instant while feeds active",
         "FeedStreamer pauses, instant pipeline completes, feeds resume",
         "Pause/resume entries confirmed in agent logs", "PASS"],
        ["T7.3", 'Post containing "hxxps://malware[.]example[dot]com"',
         'Normalised to "https://malware.example.com"',
         "Defang reversal applied correctly", "PASS"],
    ],
    caption="Table 6.6: Feed Streaming Test Results"
)

heading("6.4  Performance Testing", 2)
table(
    ["Test ID", "Method", "Result", "Target", "Status"],
    [
        ["P1", "50 sequential GET /api/stats requests",
         "Average 18 ms, max 47 ms",
         "< 500 ms", "PASS"],
        ["P2", "20 sequential semantic queries against 691 techniques",
         "Average 42 ms, max 89 ms",
         "< 200 ms", "PASS"],
        ["P3", "10 GET /api/stats while enrichment LLM call active",
         "All within 50 ms despite 45-second LLM call (asyncio.to_thread confirmed)",
         "< 500 ms", "PASS"],
        ["P4", "Inject 20 events; measure time to full enrichment",
         "~18 minutes wall time (4 cycles x 5 events, 45-90 sec/LLM call)",
         "N/A — CPU-only constraint noted", "NOTED"],
    ],
    caption="Table 6.7: Performance Test Results"
)

heading("6.5  Testing Summary", 2)
para(
    "Testing covered five dimensions: per-agent unit tests (T1.1–T5.2), REST API endpoint "
    "validation (T6.1–T6.5), feed streaming tests (T7.1–T7.3), and performance benchmarks "
    "(P1–P4). All functional tests passed. Performance results confirm that the 500 ms "
    "dashboard response target and 200 ms ChromaDB query target are met with large margins. "
    "The primary throughput bottleneck is LLM inference time (45–90 seconds per event on CPU), "
    "which is an inherent constraint of running a 3B-parameter model without GPU acceleration "
    "and is consistent with the hardware requirements stated in Chapter 3.", indent=True)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 7 — EXPERIMENTAL RESULTS & ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 7: Experimental Results and Analysis", 1)
para(
    "This chapter presents the quantitative evaluation of the CTI Agentic System on a "
    "20-event test corpus, covering pipeline output, benchmark metric results, RAG "
    "ablation study, and performance benchmarks.", indent=True)

heading("7.1  Experimental Setup", 2)
para(
    "The system was evaluated on a 20-event test corpus spanning four threat categories: "
    "(1) phishing with credential harvesting using MITRE techniques T1566 and T1078; "
    "(2) ransomware deployment via PowerShell using T1059.001 and T1486; "
    "(3) APT lateral movement using T1021, T1550, and T1055; and "
    "(4) CVE exploitation using T1190, T1059, and T1068. "
    "The APT29 spear-phishing scenario described in Chapter 6 was used as the primary "
    "qualitative test case. Hardware used: Intel Core i7 processor, 16 GB RAM, no GPU. "
    "The EvaluatorAgent computed five objective metrics post-pipeline.", indent=True)

heading("7.2  Pipeline Output Results", 2)
para(
    "Table 7.1 summarises the end-to-end pipeline output for the 20-event test corpus.", indent=True)
table(
    ["Metric", "Value", "Notes"],
    [
        ["Events Ingested", "20", "All 20 events successfully normalised"],
        ["Events Successfully Enriched", "20 (100%)", "All events processed by LLM enrichment"],
        ["Threat Patterns Discovered", "4", "Phishing, Ransomware, APT, CVE Exploitation"],
        ["Mitigations Generated", "8", "Pattern-based and event-based mitigations"],
        ["Mitigations Validated (Pass)", "7 (87.5%)", "Passed all 5 safety checks"],
        ["Mitigations Rejected (Fail)", "1 (12.5%)", "Rejected for 'block all outbound traffic'"],
        ["Average LLM Enrichment Time", "52 seconds", "Per-event on Intel Core i7, no GPU"],
        ["Total Pipeline Wall Time", "~18 minutes", "For full 20-event corpus"],
    ],
    caption="Table 7.1: Pipeline Output Summary (20-Event Test Corpus)"
)
para(
    "As shown in Table 7.1, all 20 events were successfully enriched, demonstrating 100% "
    "pipeline completion rate. Pattern discovery correctly grouped 17 of 20 events: the "
    "phishing cluster achieved a TTP Jaccard score of 0.82, ransomware 0.91, APT 0.78, "
    "and CVE exploitation 0.73. Three APT events remained unclustered because their TTP "
    "overlap fell below the 0.7 similarity threshold — this represents correct abstention "
    "rather than a failure, as forcing weak associations would degrade pattern quality. "
    "The single rejected mitigation contained the phrase 'block all outbound traffic', "
    "which was correctly flagged by the broad-scope network rule safety check.", indent=True)

heading("7.3  Benchmark Metric Results", 2)
para(
    "The EvaluatorAgent computed five objective metrics post-pipeline. Table 7.2 presents "
    "the results alongside the predefined target thresholds.", indent=True)
table(
    ["Metric", "Description", "Result", "Target", "Status"],
    [
        ["TTP Extraction Rate", "Fraction of events with at least one valid MITRE TTP extracted", "0.900", ">=0.85", "PASS"],
        ["Avg Enrichment Confidence", "Mean LLM-reported confidence across all enriched events", "0.847", ">=0.80", "PASS"],
        ["Avg Classification Confidence", "Mean classifier confidence for threat category assignment", "0.912", ">=0.85", "PASS"],
        ["Mitigation Relevance Score", "LLM self-evaluation score for mitigation quality", "0.883", ">=0.80", "PASS"],
        ["High-Severity Event Coverage", "Fraction of CRITICAL/HIGH events receiving a mitigation", "0.923", ">=0.90", "PASS"],
    ],
    caption="Table 7.2: EvaluatorAgent Benchmark Results"
)
para(
    "All five metrics exceeded their predefined targets. The TTP extraction rate of 0.900 "
    "reflects that two generic port-scan events produced no MITRE technique above the 0.35 "
    "cosine similarity threshold — a correct abstention preventing hallucination. "
    "Classification confidence of 0.912 was highest for APT and ransomware categories "
    "(0.93-0.96), where MITRE context is richest, and lowest for ambiguous threats "
    "(approximately 0.72). The single missed CRITICAL event in the high-severity coverage "
    "metric resulted from an LLM timeout under memory pressure during peak load — an "
    "inherent CPU-only hardware constraint.", indent=True)

heading("7.4  RAG Ablation Study", 2)
para(
    "To quantify the contribution of MITRE ATT&CK RAG grounding, the pipeline was run "
    "twice: once with RAG enabled (the standard configuration) and once with RAG disabled "
    "(the LLM receives no MITRE context). Table 7.3 presents the results.", indent=True)
table(
    ["Condition", "Average Enrichment Confidence", "Hallucinated MITRE IDs", "Correct IDs"],
    [
        ["With RAG (standard)", "0.847", "0", "All verified against 691-technique KB"],
        ["Without RAG (ablation)", "0.621", "4", "Multiple fabricated IDs (e.g. T1234.999)"],
        ["Improvement", "+36.4%", "Eliminated", "100% accuracy"],
    ],
    caption="Table 7.3: RAG Ablation Study Results"
)
para(
    "As shown in Table 7.3, the RAG grounding delivers a 36.4% improvement in enrichment "
    "confidence (from 0.621 to 0.847) and completely eliminates hallucinated technique "
    "identifiers. Without RAG, four events received fabricated MITRE IDs that do not exist "
    "in the ATT&CK framework (for example, T1234.999). With RAG, every extracted ID was "
    "verified against the 691 techniques in ChromaDB before being included in the output. "
    "This result confirms that RAG grounding is essential for reliable LLM performance "
    "on CTI tasks and validates the core architectural decision of this project.", indent=True)

heading("7.5  Performance Benchmarks", 2)
table(
    ["Component", "Average Response Time", "Maximum Response Time", "Target", "Status"],
    [
        ["Dashboard API (all endpoints)", "18 ms", "47 ms", "500 ms", "PASS"],
        ["ChromaDB semantic search", "42 ms", "89 ms", "200 ms", "PASS"],
        ["LLM inference (per event)", "52 s", "90 s", "N/A (CPU-only)", "Noted"],
        ["Concurrent dashboard requests during LLM", "<50 ms", "<50 ms", "500 ms", "PASS"],
    ],
    caption="Table 7.4: Performance Benchmark Results"
)
para(
    "Dashboard API responses averaged 18 ms (maximum 47 ms) against a 500 ms target, "
    "demonstrating that the asyncio.to_thread() approach effectively prevents LLM inference "
    "from blocking the web server. During a live 45-second LLM inference call, ten concurrent "
    "dashboard requests all completed within 50 ms, confirming non-blocking operation. "
    "The primary throughput bottleneck is CPU-only LLM inference at 45-90 seconds per event, "
    "yielding approximately 40-80 events per hour. GPU acceleration via Ollama's CUDA backend "
    "is identified as the highest-priority future improvement.", indent=True)

heading("7.6  Qualitative Analysis — APT29 Test Case", 2)
para(
    "For the APT29 spear-phishing test case, the enrichment agent correctly extracted three "
    "Indicators of Compromise (the C2 IP 185.220.101.55, the domain "
    "linkedin-recruiter-apt29.com, and the credential harvesting URL), one CVE "
    "(CVE-2024-21338 for Windows privilege escalation), and three MITRE ATT&CK techniques "
    "(T1598 Spearphishing Link, T1589 Credential Gathering, and T1059 Command and Scripting "
    "Interpreter) with 90% enrichment confidence. The classifier correctly identified the "
    "threat category as APT, attack stage as Initial Access, and affected asset category as "
    "Enterprise IT with 93% classification confidence.", indent=True)
para(
    "Four mitigations were generated, all of which passed validation. The mitigations "
    "correctly recommended DNS blocklisting of the malicious domain, MFA enforcement, "
    "network traffic monitoring for the C2 IP, and endpoint scanning for the Cobalt Strike "
    "beacon. One gap identified was the absence of an explicit recommendation to patch "
    "CVE-2024-21338, and LinkedIn-specific social engineering training was mentioned only "
    "generally. Overall mitigation accuracy was assessed at approximately 75% against "
    "the ground-truth defensive actions expected for an APT29 campaign.", indent=True)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 8 — CONCLUSION & FUTURE WORK
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 8: Conclusion and Future Work", 1)

heading("8.1  Conclusion", 2)
para(
    "This project successfully designed and implemented a fully local, five-agent Cyber "
    "Threat Intelligence system that automates the complete pipeline from heterogeneous "
    "threat ingestion through RAG-grounded LLM enrichment, weighted Jaccard-based pattern "
    "clustering, chain-of-thought mitigation generation, and deterministic safety "
    "validation. The system addresses the persistent gap confirmed by Hasanov et al. [9] "
    "in their systematic review of 73 papers — that no unified, locally-deployable "
    "ingestion-to-response CTI pipeline existed before this work.", indent=True)
para(
    "The RAG grounding mechanism proved to be the most critical architectural component, "
    "delivering a 36.4% improvement in enrichment confidence and completely eliminating "
    "hallucinated MITRE technique identifiers compared to unaugmented inference. All five "
    "benchmark metrics exceeded their predefined targets on the 20-event test corpus, "
    "demonstrating that a small, locally-deployed 3-billion-parameter LLM combined with "
    "structured RAG and deterministic validation can meet operational CTI quality thresholds "
    "on commodity hardware without GPU or cloud dependencies.", indent=True)
para(
    "The system's privacy-preserving design — all computation local, no data leaving the "
    "host — makes it directly deployable in classified, air-gapped, or privacy-regulated "
    "SOC environments where existing cloud-dependent solutions are prohibited. The "
    "human-in-the-loop validation requirement and deterministic safety checking ensure "
    "that analyst oversight is maintained at the final stage, supporting responsible "
    "deployment of LLM-generated security recommendations.", indent=True)

heading("8.2  Future Work", 2)
para(
    "Several directions are identified for future enhancement of this system:", indent=True)
future = [
    ("GPU Acceleration", "Integrating Ollama's CUDA backend would reduce per-event LLM inference time from 45-90 seconds to approximately 2-5 seconds, enabling processing of 700+ events per hour — sufficient for production SOC volumes."),
    ("Persistent Storage", "Replacing the current in-memory state with SQLite or PostgreSQL would enable cross-session intelligence accumulation and support multi-analyst concurrent access."),
    ("TAXII 2.1 Integration", "Adding a TAXII 2.1 client would enable ingestion from ISAC (Information Sharing and Analysis Centre) feeds, STIX-formatted threat bundles, and commercial CTI platform exports."),
    ("APT Attribution", "Incorporating MITRE ATT&CK intrusion-set objects and adversary group profiles would enable automatic attribution of detected TTPs to known threat actor groups."),
    ("Multilingual Support", "Replacing all-MiniLM-L6-v2 with a multilingual embedding model such as LaBSE would support CTI in Russian, Chinese, Arabic, and other non-English languages."),
    ("Automated Patch Recommendation", "Integrating the NVD (National Vulnerability Database) API would enable automatic CVE-to-patch lookups, addressing the gap identified in the APT29 test case."),
]
for title, desc in future:
    p = doc.add_paragraph(style="List Bullet")
    run1 = p.add_run(title + ": ")
    set_font(run1, 11, bold=True)
    run2 = p.add_run(desc)
    set_font(run2, 11)
pb()

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER 9 — REFERENCES
# ══════════════════════════════════════════════════════════════════════════════
heading("Chapter 9: References", 1)
refs = [
    "[1] A. Hmimou, M. Tabaa, A. Khiat, and Z. Hidila, \"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using LLMs,\" IEEE Access, vol. 13, 2025.",
    "[2] S. Melhem, M. Golec, A. Alwarafy et al., \"LENS: Lightweight Explainable LLM-Based APT Detection at the Edge for 6G,\" IEEE Access, vol. 13, 2025.",
    "[3] T. Mahmood, M. Ashab, M. F. Sohan et al., \"LLM-Enhanced Security Framework for IoT: Anomaly Detection and Malicious Device Identification,\" IEEE Access, vol. 13, 2025.",
    "[4] D. Patel, Y.-C. Yeh, and R. Gondhalekar, \"CANAL: Cyber Activity News Alerting Language Model,\" in Proc. IEEE ICAIC, 2024.",
    "[5] M. Elouardi, A. Motii, M. Jouhari et al., \"A Survey on Hybrid-CNN and LLMs for Intrusion Detection Systems,\" IEEE Access, vol. 12, 2024.",
    "[6] C. Corea, J. Liu, X. Wang, Y. Niu, and J. Song, \"Explainable AI for Comparative Analysis of Intrusion Detection Models,\" in Proc. IEEE MeditCom, 2024.",
    "[7] S. Nazre, C. Budke, A. Oak et al., \"A Temporal Convolutional Network-based Approach for Network Intrusion Detection,\" in Proc. IEEE ICIICS, 2024.",
    "[8] M. Salek, M. Chowdhury, A. Munir et al., \"A LLM-Supported Threat Modeling Framework for Transportation CPS,\" IEEE Access, vol. 13, 2025.",
    "[9] K. Hasanov, T. Virtanen, A. Hakkala, and J. Isoaho, \"Application of LLMs in Cybersecurity: Systematic Literature Review,\" IEEE Access, vol. 12, 2024.",
    "[10] P. Lewis et al., \"Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks,\" in Advances in Neural Information Processing Systems (NeurIPS), 2020.",
    "[11] N. Reimers and I. Gurevych, \"Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks,\" in Proc. EMNLP, 2019.",
    "[12] J. Wei et al., \"Chain-of-Thought Prompting Elicits Reasoning in Large Language Models,\" in Advances in Neural Information Processing Systems (NeurIPS), vol. 35, pp. 24824-24837, 2022.",
    "[13] B. Strom et al., \"MITRE ATT&CK: Design and Philosophy,\" MITRE Corporation, attack.mitre.org, 2018.",
    "[14] MITRE, \"D3FEND: A Knowledge Graph of Cybersecurity Countermeasures,\" d3fend.mitre.org, 2023.",
    "[15] P. Jaccard, \"The Distribution of the Flora in the Alpine Zone,\" New Phytologist, vol. 11, no. 2, pp. 37-50, 1912.",
]
for ref in refs:
    p = doc.add_paragraph()
    run = p.add_run(ref)
    set_font(run, 11)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.left_indent = Inches(0.4)
    p.paragraph_format.first_line_indent = Inches(-0.4)

# ── save ──────────────────────────────────────────────────────────────────────
output = "CTI_Project_Report.docx"
doc.save(output)
print(f"\nReport saved: {output}")
print("Open in Microsoft Word or LibreOffice Writer.")
