"""
Agent 4: Mitigation Agent
Generates mitigation recommendations and security rules using LLM
"""
import hashlib
from typing import List, Optional
from datetime import datetime

from models import (ThreatPattern, EnrichedEvent, MitigationAction, 
                    SeverityLevel, AgentLogEntry)
from llm_wrapper import LLMWrapper
import config


class MitigationAgent:
    """Agent responsible for generating mitigation recommendations"""
    
    def __init__(self, llm: LLMWrapper):
        self.name = "MitigationAgent"
        self.llm = llm
        self.log_entries: List[AgentLogEntry] = []
        self.mitigations: List[MitigationAction] = []
    
    def _log(self, action: str, details: str, mitigation_id: str = None, 
             pattern_id: str = None, status: str = "success"):
        """Create log entry"""
        entry = AgentLogEntry(
            agent_name=self.name,
            action=action,
            details=details,
            mitigation_id=mitigation_id,
            pattern_id=pattern_id,
            status=status
        )
        self.log_entries.append(entry)
        return entry
    
    def _generate_mitigation_id(self, context: str) -> str:
        """Generate unique mitigation ID"""
        key = f"{context}_{datetime.now().isoformat()}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    def _build_pattern_mitigation_prompt(self, pattern: ThreatPattern) -> str:
        """Build prompt for pattern mitigation"""
        prompt = f"""Generate cybersecurity mitigation recommendations for the following threat pattern.

Pattern Details:
- Name: {pattern.pattern_name}
- Description: {pattern.description}
- Severity: {pattern.severity.name}
- Event Count: {pattern.event_count}
- Common TTPs: {', '.join(pattern.common_ttps[:3]) if pattern.common_ttps else 'None'}
- Affected Systems: {', '.join(pattern.affected_systems) if pattern.affected_systems else 'Unknown'}

Provide mitigation in JSON format with:
1. "title": Short mitigation title (5-10 words)
2. "description": Brief overview of the mitigation strategy (1-2 sentences)
3. "steps": Array of 3-5 specific, actionable mitigation steps
4. "sample_rule": One sample security rule (firewall, IDS, SIEM) if applicable (or null)
5. "priority": Integer 1-5 (1=low, 5=critical)

The mitigation should be:
- Practical and implementable
- Specific to the threat pattern
- Include both preventive and detective controls
- Consider the affected systems

Return ONLY valid JSON, no additional text.

Example format:
{{
  "title": "Block Malicious Phishing Domains",
  "description": "Implement DNS and email filtering to block known phishing domains and prevent credential theft.",
  "steps": [
    "Update DNS blocklists with identified malicious domains",
    "Configure email gateway to quarantine emails from flagged domains",
    "Enable MFA on all user accounts to mitigate credential theft",
    "Conduct user awareness training on phishing identification",
    "Monitor for authentication anomalies using SIEM"
  ],
  "sample_rule": "firewall rule deny ip any any to domain-list phishing-domains",
  "priority": 4
}}"""
        return prompt
    
    def _build_event_mitigation_prompt(self, event: EnrichedEvent) -> str:
        """Build prompt for single high-severity event"""
        prompt = f"""Generate cybersecurity mitigation recommendations for this high-severity threat event.

Event Details:
- Type: {event.original_event.event_type}
- Severity: {event.original_event.severity.name}
- Description: {event.original_event.raw_text[:500]}
- Indicator: {event.original_event.indicator or 'N/A'}
- TTPs: {', '.join(event.ttps[:3]) if event.ttps else 'None'}
- IOCs: {', '.join([f"{ioc.get('type')}:{ioc.get('value')}" for ioc in event.iocs[:5]]) if event.iocs else 'None'}
- Attack Vector: {event.attack_vector or 'Unknown'}
- Affected Assets: {', '.join(event.affected_assets) if event.affected_assets else 'Unknown'}

Provide mitigation in JSON format with:
1. "title": Short mitigation title (5-10 words)
2. "description": Brief overview (1-2 sentences)
3. "steps": Array of 3-5 specific, actionable steps
4. "sample_rule": One sample security rule if applicable (or null)
5. "priority": Integer 1-5 based on severity

Return ONLY valid JSON.

Example format:
{{
  "title": "Block Malicious IP and Isolate Affected Host",
  "description": "Immediately block the malicious IP address and isolate potentially compromised systems for investigation.",
  "steps": [
    "Add IP 192.168.1.100 to firewall blocklist",
    "Isolate affected host from network",
    "Run full malware scan on isolated system",
    "Review logs for lateral movement attempts",
    "Reset credentials for accounts accessed from compromised host"
  ],
  "sample_rule": "iptables -A INPUT -s 192.168.1.100 -j DROP",
  "priority": 4
}}"""
        return prompt
    
    async def generate_for_pattern(self, pattern: ThreatPattern) -> Optional[MitigationAction]:
        """Generate mitigation for a threat pattern"""
        try:
            # Build prompt
            prompt = self._build_pattern_mitigation_prompt(pattern)
            
            system_prompt = """You are a cybersecurity incident response expert.
Generate practical, actionable mitigation recommendations for threat patterns.
Focus on defense-in-depth strategies covering prevention, detection, and response.
Output only valid JSON matching the requested schema."""
            
            # Call LLM (async to avoid blocking event loop)
            result = await self.llm.agenerate_json(prompt, system_prompt)
            
            if not result:
                self._log("generate_for_pattern", 
                         f"LLM returned no result for pattern {pattern.pattern_id}",
                         pattern_id=pattern.pattern_id, status="warning")
                return None
            
            # Create mitigation action
            mitigation = MitigationAction(
                mitigation_id=self._generate_mitigation_id(f"pattern_{pattern.pattern_id}"),
                pattern_id=pattern.pattern_id,
                title=result.get('title', 'Mitigation for ' + pattern.pattern_name),
                description=result.get('description', ''),
                steps=result.get('steps', []),
                sample_rule=result.get('sample_rule'),
                priority=SeverityLevel(result.get('priority', 3)),
                status='under_review'
            )
            
            self.mitigations.append(mitigation)
            
            self._log("generate_for_pattern",
                     f"Generated mitigation for pattern {pattern.pattern_name}: {mitigation.title}",
                     mitigation_id=mitigation.mitigation_id,
                     pattern_id=pattern.pattern_id)
            
            return mitigation
        
        except Exception as e:
            self._log("generate_for_pattern",
                     f"Error generating mitigation for pattern {pattern.pattern_id}: {str(e)}",
                     pattern_id=pattern.pattern_id, status="error")
            return None
    
    async def generate_for_event(self, event: EnrichedEvent) -> Optional[MitigationAction]:
        """Generate mitigation for high-severity single event"""
        try:
            # Only generate for high-severity events
            if event.original_event.severity < config.MIN_SEVERITY_FOR_MITIGATION:
                return None
            
            prompt = self._build_event_mitigation_prompt(event)
            
            system_prompt = """You are a cybersecurity incident responder.
Generate immediate, practical mitigation steps for high-severity threats.
Focus on containment, eradication, and recovery actions.
Output only valid JSON."""
            
            # Call LLM (async to avoid blocking event loop)
            result = await self.llm.agenerate_json(prompt, system_prompt)
            
            if not result:
                self._log("generate_for_event",
                         f"LLM returned no result for event {event.event_id}",
                         status="warning")
                return None
            
            mitigation = MitigationAction(
                mitigation_id=self._generate_mitigation_id(f"event_{event.event_id}"),
                event_id=event.event_id,
                title=result.get('title', 'Mitigation for threat event'),
                description=result.get('description', ''),
                steps=result.get('steps', []),
                sample_rule=result.get('sample_rule'),
                priority=SeverityLevel(result.get('priority', 3)),
                status='under_review'
            )
            
            self.mitigations.append(mitigation)
            
            self._log("generate_for_event",
                     f"Generated mitigation for event {event.event_id}: {mitigation.title}",
                     mitigation_id=mitigation.mitigation_id)
            
            return mitigation
        
        except Exception as e:
            self._log("generate_for_event",
                     f"Error generating mitigation for event {event.event_id}: {str(e)}",
                     status="error")
            return None
    
    async def generate_mitigations(self, patterns: List[ThreatPattern], 
                                   high_severity_events: List[EnrichedEvent]) -> List[MitigationAction]:
        """Generate mitigations for patterns and high-severity events"""
        new_mitigations = []
        
        # Generate for patterns
        self._log("generate_mitigations", f"Generating mitigations for {len(patterns)} patterns")
        
        for pattern in patterns:
            mitigation = await self.generate_for_pattern(pattern)
            if mitigation:
                new_mitigations.append(mitigation)
        
        # Generate for high-severity events
        high_sev = [e for e in high_severity_events 
                    if e.original_event.severity >= config.MIN_SEVERITY_FOR_MITIGATION]
        
        if high_sev:
            self._log("generate_mitigations", 
                     f"Generating mitigations for {len(high_sev)} high-severity events")
            
            for event in high_sev[:10]:  # Limit to avoid too many
                mitigation = await self.generate_for_event(event)
                if mitigation:
                    new_mitigations.append(mitigation)
        
        self._log("generate_mitigations", 
                 f"Generated {len(new_mitigations)} total mitigations")
        
        return new_mitigations
    
    def get_all_mitigations(self) -> List[MitigationAction]:
        """Get all generated mitigations"""
        return self.mitigations
