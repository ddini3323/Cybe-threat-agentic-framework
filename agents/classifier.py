"""
Agent: Threat Classifier  (Objective 2)
Classifies enriched threat events using LLM into threat categories,
MITRE ATT&CK kill-chain stages, severity justifications, and asset categories.

Research basis: Gaps identified in P2 (Hasanov et al., IEEE Access 2024),
P5 (Elouardi et al., IEEE Access 2024), P10 (Feng & Sakurai, arXiv 2025)
"""
from typing import List, Optional
from datetime import datetime

from models import EnrichedEvent, ThreatClassification, AgentLogEntry
from llm_wrapper import LLMWrapper

# MITRE ATT&CK tactic names for attack-stage mapping
ATTACK_STAGES = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

THREAT_CATEGORIES = [
    "APT", "Ransomware", "Phishing", "DDoS", "Malware", "Insider Threat",
    "Supply Chain Attack", "Cryptojacking", "Data Breach", "Web Application Attack",
    "Brute Force", "Zero-Day Exploit", "Social Engineering", "Unknown",
]

ASSET_CATEGORIES = [
    "Enterprise IT", "Critical Infrastructure", "Cloud Services",
    "IoT / OT", "Mobile", "Web Application", "Database", "Network Device", "Unknown",
]


class ClassifierAgent:
    """Agent that classifies threats using LLM contextual reasoning (Objective 2)"""

    def __init__(self, llm: LLMWrapper):
        self.name = "ClassifierAgent"
        self.llm = llm
        self.log_entries: List[AgentLogEntry] = []
        self.classifications: List[ThreatClassification] = []

    def _log(self, action: str, details: str, event_id: str = None, status: str = "success"):
        entry = AgentLogEntry(
            agent_name=self.name,
            action=action,
            details=details,
            event_id=event_id,
            status=status
        )
        self.log_entries.append(entry)
        return entry

    def _build_classification_prompt(self, event: EnrichedEvent) -> str:
        ttp_list = ", ".join(event.ttps[:5]) if event.ttps else "None identified"
        ioc_summary = ", ".join(
            [f"{i.get('type')}:{i.get('value')}" for i in event.iocs[:3]]
        ) if event.iocs else "None"
        cve_list = ", ".join(event.cves[:3]) if event.cves else "None"

        return f"""You are a senior cyber threat intelligence analyst. Classify the following threat event.

Threat Event:
- Raw text: {event.original_event.raw_text[:600]}
- Indicator: {event.original_event.indicator or 'N/A'}
- Type: {event.original_event.event_type}
- Severity assigned: {event.original_event.severity.name}
- Extracted TTPs: {ttp_list}
- Extracted IOCs: {ioc_summary}
- CVEs: {cve_list}
- Malware family: {event.malware_family or 'Unknown'}
- Attack vector: {event.attack_vector or 'Unknown'}

Available threat categories: {', '.join(THREAT_CATEGORIES)}
Available attack stages (MITRE ATT&CK): {', '.join(ATTACK_STAGES)}
Available asset categories: {', '.join(ASSET_CATEGORIES)}

Classify this threat and return JSON with:
1. "threat_category": Most fitting category from the list above
2. "attack_stage": Most fitting MITRE ATT&CK stage from the list above
3. "severity_justification": 1-2 sentence explanation of why the assigned severity is correct
4. "affected_asset_category": Most fitting asset category from the list above
5. "classification_confidence": Float 0-1 based on how clear the indicators are

Return ONLY valid JSON. Example:
{{
  "threat_category": "Ransomware",
  "attack_stage": "Impact",
  "severity_justification": "Ransomware encrypts critical files and demands payment, causing business disruption — CRITICAL severity is appropriate.",
  "affected_asset_category": "Enterprise IT",
  "classification_confidence": 0.88
}}"""

    async def classify_event(self, event: EnrichedEvent) -> Optional[ThreatClassification]:
        """Classify a single enriched event using LLM"""
        try:
            prompt = self._build_classification_prompt(event)
            system_prompt = (
                "You are a cyber threat intelligence classification expert. "
                "Classify threats accurately based on TTPs, IOCs, and context. "
                "Output only valid JSON."
            )
            result = await self.llm.agenerate_json(prompt, system_prompt)

            if not result:
                self._log("classify_event",
                          f"LLM returned no classification for {event.event_id}",
                          event.event_id, status="warning")
                return None

            classification = ThreatClassification(
                event_id=event.event_id,
                threat_category=result.get("threat_category", "Unknown"),
                attack_stage=result.get("attack_stage", "Unknown"),
                severity_justification=result.get("severity_justification", ""),
                affected_asset_category=result.get("affected_asset_category", "Unknown"),
                classification_confidence=float(result.get("classification_confidence", 0.5)),
                classified_at=datetime.now(),
            )

            # Deduplicate — replace any existing classification for this event
            self.classifications = [
                c for c in self.classifications if c.event_id != event.event_id
            ]
            self.classifications.append(classification)
            self._log(
                "classify_event",
                f"Classified {event.event_id}: {classification.threat_category} "
                f"| Stage: {classification.attack_stage} "
                f"| Confidence: {classification.classification_confidence:.2f}",
                event.event_id,
            )
            return classification

        except Exception as e:
            self._log("classify_event",
                      f"Error classifying event {event.event_id}: {e}",
                      event.event_id, status="error")
            return None

    async def classify_batch(self, events: List[EnrichedEvent]) -> List[ThreatClassification]:
        """Classify a batch of enriched events"""
        results = []
        self._log("classify_batch", f"Classifying {len(events)} events")

        for event in events:
            classification = await self.classify_event(event)
            if classification:
                results.append(classification)

        self._log("classify_batch",
                  f"Completed: {len(results)}/{len(events)} events classified")
        return results

    def get_all_classifications(self) -> List[ThreatClassification]:
        return self.classifications
