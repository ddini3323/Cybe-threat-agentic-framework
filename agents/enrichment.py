"""
Agent 2: Enrichment & Extraction Agent
Uses LLM to extract IOCs, CVEs, TTPs from threat events
"""
from typing import List, Optional
from datetime import datetime

from models import ThreatEvent, EnrichedEvent, AgentLogEntry
from llm_wrapper import LLMWrapper
import config


class EnrichmentAgent:
    """Agent responsible for enriching threat events using LLM"""
    
    def __init__(self, llm: LLMWrapper):
        self.name = "EnrichmentAgent"
        self.llm = llm
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
    
    def _build_extraction_prompt(self, event: ThreatEvent) -> str:
        """Build prompt for LLM extraction"""
        prompt = f"""Extract cybersecurity threat intelligence from the following threat event.

Event Details:
- Type: {event.event_type}
- Source: {event.source}
- Indicator: {event.indicator or 'N/A'}
- Description: {event.raw_text}

Extract and return the following in JSON format:
1. "iocs": List of Indicators of Compromise (IP addresses, URLs, domains, file hashes, emails). Each as {{"type": "IP|URL|Domain|Hash|Email", "value": "actual_value"}}
2. "cves": List of CVE identifiers (e.g., CVE-2023-1234)
3. "ttps": List of MITRE ATT&CK TTPs in format "T#### - Brief Description" (e.g., "T1059 - Command and Scripting Interpreter")
4. "affected_assets": List of affected system types (e.g., "Windows", "Linux", "Webserver", "Network Device")
5. "malware_family": Name of malware family if mentioned (or null)
6. "attack_vector": Primary attack vector (e.g., "Phishing", "Exploit", "Brute Force", or null)
7. "confidence": Float 0-1 indicating extraction confidence

Return ONLY valid JSON, no additional text.

Example response format:
{{
  "iocs": [{{"type": "IP", "value": "192.168.1.1"}}, {{"type": "URL", "value": "http://malicious.com"}}],
  "cves": ["CVE-2023-1234"],
  "ttps": ["T1059 - Command-Line Interface", "T1566 - Phishing"],
  "affected_assets": ["Windows", "Office 365"],
  "malware_family": "Emotet",
  "attack_vector": "Phishing",
  "confidence": 0.85
}}"""
        return prompt
    
    async def enrich_event(self, event: ThreatEvent) -> Optional[EnrichedEvent]:
        """Enrich a single event using LLM"""
        try:
            # Build prompt
            prompt = self._build_extraction_prompt(event)
            
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
            
            # Parse result
            enriched = EnrichedEvent(
                event_id=event.event_id,
                original_event=event,
                iocs=result.get('iocs', []),
                cves=result.get('cves', []),
                ttps=result.get('ttps', []),
                affected_assets=result.get('affected_assets', []),
                malware_family=result.get('malware_family'),
                attack_vector=result.get('attack_vector'),
                enrichment_confidence=result.get('confidence', 0.5)
            )
            
            # Log success
            ioc_count = len(enriched.iocs)
            ttp_count = len(enriched.ttps)
            self._log("enrich_event", 
                     f"Enriched event {event.event_id}: {ioc_count} IOCs, {ttp_count} TTPs extracted",
                     event.event_id)
            
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
