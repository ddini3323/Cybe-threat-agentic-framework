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
        """Build chain-of-thought prompt for pattern mitigation (Objective 3)"""
        prompt = f"""You are a cybersecurity incident response expert. Generate explainable mitigation recommendations for the threat pattern below.

Think step-by-step before answering:
1. What is the primary threat mechanism of this pattern?
2. Which MITRE D3FEND countermeasures apply?
3. What is the minimal effective mitigation that avoids disrupting operations?

Threat Pattern:
- Name: {pattern.pattern_name}
- Description: {pattern.description}
- Severity: {pattern.severity.name}
- Event Count: {pattern.event_count}
- Common TTPs: {', '.join(pattern.common_ttps[:3]) if pattern.common_ttps else 'None'}
- Affected Systems: {', '.join(pattern.affected_systems) if pattern.affected_systems else 'Unknown'}

MITRE D3FEND countermeasure categories (pick the most relevant 1-3):
- D3-NI: Network Isolation | D3-ITF: Inbound Traffic Filtering | D3-OTF: Outbound Traffic Filtering
- D3-UA: User Account Restrictions | D3-MFA: Multi-Factor Authentication | D3-EDR: Endpoint Detection & Response
- D3-PA: Process Allowlisting | D3-PM: Process Monitoring | D3-FH: File Hash Denylisting
- D3-NTA: Network Traffic Analysis | D3-DNSDL: DNS Denylisting | D3-EI: Email Filtering

Provide mitigation in JSON format:
1. "reasoning": 2-3 sentence chain-of-thought explanation of WHY these specific steps address this threat
2. "title": Short mitigation title (5-10 words)
3. "description": Brief overview of the mitigation strategy (1-2 sentences)
4. "steps": Array of 3-5 specific, actionable mitigation steps
5. "sample_rule": One sample security rule (firewall, IDS, SIEM) if applicable (or null)
6. "mitre_d3fend": Array of 1-3 applicable D3FEND countermeasure IDs (e.g., ["D3-NI", "D3-ITF"])
7. "priority": Integer 1-5 (1=low, 5=critical)

Return ONLY valid JSON.

Example:
{{
  "reasoning": "This phishing pattern exploits email trust to deliver malware. Blocking at the email gateway prevents delivery, while MFA limits credential theft impact. Network isolation stops lateral movement if a host is compromised.",
  "title": "Block Phishing Domains and Enforce MFA",
  "description": "Implement layered email filtering and enforce MFA to prevent phishing-driven credential theft.",
  "steps": [
    "Update DNS blocklists with identified malicious domains",
    "Configure email gateway to quarantine emails from flagged senders",
    "Enforce MFA on all accounts to limit credential theft impact",
    "Monitor SIEM for authentication anomalies from affected users",
    "Conduct targeted phishing awareness training"
  ],
  "sample_rule": "alert smtp any any -> $MAIL_SERVERS any (msg:\"Phishing domain detected\"; content:\"malicious-domain.com\"; sid:1000001;)",
  "mitre_d3fend": ["D3-MFA", "D3-DNSDL", "D3-ITF"],
  "priority": 4
}}"""
        return prompt

    def _build_event_mitigation_prompt(self, event: EnrichedEvent) -> str:
        """Build chain-of-thought prompt for high-severity event (Objective 3)"""
        prompt = f"""You are a cybersecurity incident responder. Generate explainable, immediate mitigation for this high-severity threat.

Think step-by-step:
1. What is the immediate risk if no action is taken?
2. What is the fastest containment action?
3. What detection or monitoring should be added?

Event Details:
- Type: {event.original_event.event_type}
- Severity: {event.original_event.severity.name}
- Description: {event.original_event.raw_text[:500]}
- Indicator: {event.original_event.indicator or 'N/A'}
- TTPs: {', '.join(event.ttps[:3]) if event.ttps else 'None'}
- IOCs: {', '.join([f"{i.get('type')}:{i.get('value')}" for i in event.iocs[:5]]) if event.iocs else 'None'}
- Attack Stage: {event.attack_stage or 'Unknown'}
- Attack Vector: {event.attack_vector or 'Unknown'}
- Affected Assets: {', '.join(event.affected_assets) if event.affected_assets else 'Unknown'}
- Threat Category: {event.threat_category or 'Unknown'}

MITRE D3FEND categories: D3-NI (Network Isolation), D3-ITF (Inbound Filtering), D3-OTF (Outbound Filtering),
D3-UA (User Account Restrictions), D3-MFA (Multi-Factor Auth), D3-EDR (Endpoint Detection),
D3-PA (Process Allowlisting), D3-FH (File Hash Denylisting), D3-NTA (Network Traffic Analysis)

Provide mitigation in JSON format:
1. "reasoning": 2-3 sentence explanation of WHY these steps address this specific threat context
2. "title": Short mitigation title (5-10 words)
3. "description": Brief overview (1-2 sentences)
4. "steps": Array of 3-5 specific, actionable steps
5. "sample_rule": One sample security rule if applicable (or null)
6. "mitre_d3fend": Array of 1-3 applicable D3FEND IDs
7. "priority": Integer 1-5 based on severity

Return ONLY valid JSON."""
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
            
            # Create mitigation action with O3 explainability fields
            mitigation = MitigationAction(
                mitigation_id=self._generate_mitigation_id(f"pattern_{pattern.pattern_id}"),
                pattern_id=pattern.pattern_id,
                title=result.get('title', 'Mitigation for ' + pattern.pattern_name),
                description=result.get('description', ''),
                steps=result.get('steps', []),
                sample_rule=result.get('sample_rule'),
                reasoning=result.get('reasoning'),
                mitre_d3fend=result.get('mitre_d3fend', []),
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
                reasoning=result.get('reasoning'),
                mitre_d3fend=result.get('mitre_d3fend', []),
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
