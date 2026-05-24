"""
Agent 2: Enrichment & Extraction Agent
Uses LLM to extract IOCs, CVEs, TTPs from threat events.
Optionally uses RAG (ChromaDB + MITRE ATT&CK) for better TTP mapping.
"""
from typing import List, Optional
from datetime import datetime

from models import ThreatEvent, EnrichedEvent, AgentLogEntry
from llm_wrapper import LLMWrapper
import config


class EnrichmentAgent:
    """Agent responsible for enriching threat events using LLM"""

    def __init__(self, llm: LLMWrapper, retriever=None):
        self.name = "EnrichmentAgent"
        self.llm = llm
        self.retriever = retriever  # Optional CTIRetriever for RAG
        self.log_entries: List[AgentLogEntry] = []

    def _log(self, action: str, details: str, event_id: str = None, status: str = "success"):
        """Create log entry"""
        entry = AgentLogEntry(
            agent_name=self.name,
            action=action,
            details=details,
            event_id=event_id,
            status=status
        )
        self.log_entries.append(entry)
        return entry
    
    def _build_extraction_prompt(self, event: ThreatEvent, rag_context: str = "") -> str:
        """Build prompt for LLM extraction with enhanced MITRE ATT&CK context (Objective 1)"""
        rag_section = ""
        if rag_context:
            rag_section = f"""

Knowledge Base Context (MITRE ATT&CK + historical threats):
{rag_context}

Use the above context to improve TTP and tactic mapping accuracy.
"""
        prompt = f"""You are a cyber threat intelligence analyst. Extract structured threat intelligence from the event below.{rag_section}
Event Details:
- Type: {event.event_type}
- Source: {event.source}
- Indicator: {event.indicator or 'N/A'}
- Description: {event.raw_text}

Extract and return the following in JSON format:
1. "iocs": List of Indicators of Compromise. Each as {{"type": "IP|URL|Domain|Hash|Email", "value": "actual_value"}}
2. "cves": List of CVE identifiers (e.g., ["CVE-2023-1234"])
3. "ttps": List of MITRE ATT&CK technique IDs + names, format "T#### - Name" (e.g., ["T1059 - Command and Scripting Interpreter"])
4. "mitre_tactics": List of MITRE ATT&CK tactic IDs + names this event maps to, format "TA#### - Tactic Name" (e.g., ["TA0001 - Initial Access", "TA0002 - Execution"])
5. "attack_stage": The single most relevant MITRE ATT&CK tactic name (e.g., "Initial Access")
6. "threat_category": Threat category — one of: APT, Ransomware, Phishing, DDoS, Malware, Insider Threat, Supply Chain Attack, Cryptojacking, Data Breach, Web Application Attack, Brute Force, Zero-Day Exploit, Social Engineering, Unknown
7. "affected_assets": List of affected system types (e.g., ["Windows", "Linux", "Webserver"])
8. "malware_family": Malware family name if identified (or null)
9. "attack_vector": Primary attack vector (e.g., "Phishing", "Exploit", "Brute Force", or null)
10. "confidence": Float 0-1 indicating overall extraction confidence

Return ONLY valid JSON. Example:
{{
  "iocs": [{{"type": "IP", "value": "192.168.1.1"}}, {{"type": "URL", "value": "http://malicious.com"}}],
  "cves": ["CVE-2023-1234"],
  "ttps": ["T1059 - Command and Scripting Interpreter", "T1566 - Phishing"],
  "mitre_tactics": ["TA0001 - Initial Access", "TA0002 - Execution"],
  "attack_stage": "Initial Access",
  "threat_category": "Phishing",
  "affected_assets": ["Windows", "Office 365"],
  "malware_family": "Emotet",
  "attack_vector": "Phishing",
  "confidence": 0.85
}}"""
        return prompt
    
    async def enrich_event(self, event: ThreatEvent) -> Optional[EnrichedEvent]:
        """Enrich a single event using LLM, with optional RAG context"""
        try:
            # Build RAG context if retriever is available
            rag_context = ""
            if self.retriever and self.retriever.is_ready():
                mitre_ctx = self.retriever.get_mitre_context(event.raw_text)
                similar_ctx = self.retriever.get_similar_threats_context(event.raw_text)
                parts = [p for p in [mitre_ctx, similar_ctx] if p]
                rag_context = "\n\n".join(parts)

            # Build prompt
            prompt = self._build_extraction_prompt(event, rag_context)
            
            # System prompt for context
            system_prompt = """You are a cybersecurity threat intelligence analyst. 
Extract structured information from threat reports accurately. 
Output only valid JSON matching the requested schema."""
            
            # Call LLM (async to avoid blocking event loop)
            result = await self.llm.agenerate_json(prompt, system_prompt)
            
            if not result:
                self._log("enrich_event", f"LLM returned no result for event {event.event_id}", 
                         event.event_id, status="warning")
                # Return basic enriched event
                return EnrichedEvent(
                    event_id=event.event_id,
                    original_event=event,
                    enrichment_confidence=0.0
                )
            
            # Parse result — includes new O1 fields
            enriched = EnrichedEvent(
                event_id=event.event_id,
                original_event=event,
                iocs=result.get('iocs', []),
                cves=result.get('cves', []),
                ttps=result.get('ttps', []),
                mitre_tactics=result.get('mitre_tactics', []),
                attack_stage=result.get('attack_stage'),
                threat_category=result.get('threat_category'),
                affected_assets=result.get('affected_assets', []),
                malware_family=result.get('malware_family'),
                attack_vector=result.get('attack_vector'),
                enrichment_confidence=result.get('confidence', 0.5)
            )
            
            # Log success
            ioc_count = len(enriched.iocs)
            ttp_count = len(enriched.ttps)
            rag_note = " [RAG-assisted]" if rag_context else ""
            self._log("enrich_event",
                     f"Enriched event {event.event_id}: {ioc_count} IOCs, {ttp_count} TTPs extracted{rag_note}",
                     event.event_id)

            # Self-learning: store this enriched event for future retrieval
            if self.retriever and enriched.enrichment_confidence > 0.3:
                self.retriever.store_enriched_event(
                    event_id=event.event_id,
                    threat_text=event.raw_text,
                    source=event.source,
                    ttps=enriched.ttps,
                    malware=enriched.malware_family,
                )

            return enriched
        
        except Exception as e:
            self._log("enrich_event", f"Error enriching event {event.event_id}: {str(e)}", 
                     event.event_id, status="error")
            # Return basic enriched event on error
            return EnrichedEvent(
                event_id=event.event_id,
                original_event=event,
                enrichment_confidence=0.0
            )
    
    async def enrich_batch(self, events: List[ThreatEvent]) -> List[EnrichedEvent]:
        """Enrich a batch of events"""
        enriched_events = []
        
        self._log("enrich_batch", f"Starting enrichment of {len(events)} events")
        
        for event in events[:config.MAX_EVENTS_PER_CYCLE]:
            enriched = await self.enrich_event(event)
            if enriched:
                enriched_events.append(enriched)
        
        self._log("enrich_batch", f"Completed enrichment: {len(enriched_events)} events processed")
        
        return enriched_events
