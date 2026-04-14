"""
Agent 3: Pattern Discovery Agent
Clusters and groups related threat events into patterns
"""
import hashlib
from typing import List, Dict
from datetime import datetime
from collections import defaultdict

from models import EnrichedEvent, ThreatPattern, SeverityLevel, AgentLogEntry
import config


class PatternDiscoveryAgent:
    """Agent responsible for discovering threat patterns"""
    
    def __init__(self):
        self.name = "PatternDiscoveryAgent"
        self.log_entries: List[AgentLogEntry] = []
        self.discovered_patterns: Dict[str, ThreatPattern] = {}
    
    def _log(self, action: str, details: str, pattern_id: str = None, status: str = "success"):
        """Create log entry"""
        entry = AgentLogEntry(
            agent_name=self.name,
            action=action,
            details=details,
            pattern_id=pattern_id,
            status=status
        )
        self.log_entries.append(entry)
        return entry
    
    def _generate_pattern_id(self, pattern_name: str) -> str:
        """Generate unique pattern ID"""
        return hashlib.md5(pattern_name.encode()).hexdigest()[:16]
    
    def _calculate_similarity(self, event1: EnrichedEvent, event2: EnrichedEvent) -> float:
        """Calculate similarity between two events"""
        score = 0.0
        factors = 0
        
        # TTP overlap
        if event1.ttps and event2.ttps:
            ttps1 = set(event1.ttps)
            ttps2 = set(event2.ttps)
            if ttps1 and ttps2:
                ttp_similarity = len(ttps1 & ttps2) / len(ttps1 | ttps2)
                score += ttp_similarity * 0.4  # 40% weight
                factors += 0.4
        
        # Malware family match
        if event1.malware_family and event2.malware_family:
            if event1.malware_family.lower() == event2.malware_family.lower():
                score += 0.3  # 30% weight
            factors += 0.3
        
        # Attack vector match
        if event1.attack_vector and event2.attack_vector:
            if event1.attack_vector.lower() == event2.attack_vector.lower():
                score += 0.2  # 20% weight
            factors += 0.2
        
        # Affected assets overlap
        if event1.affected_assets and event2.affected_assets:
            assets1 = set(event1.affected_assets)
            assets2 = set(event2.affected_assets)
            if assets1 and assets2:
                asset_similarity = len(assets1 & assets2) / len(assets1 | assets2)
                score += asset_similarity * 0.1  # 10% weight
                factors += 0.1
        
        # Normalize by actual factors used
        return score / factors if factors > 0 else 0.0
    
    def _group_by_ttps(self, events: List[EnrichedEvent]) -> Dict[str, List[EnrichedEvent]]:
        """Group events by common TTPs"""
        groups = defaultdict(list)
        
        for event in events:
            if not event.ttps:
                groups['unknown'].append(event)
                continue
            
            # Use primary TTP (first one)
            primary_ttp = event.ttps[0]
            groups[primary_ttp].append(event)
        
        return groups
    
    def _group_by_malware(self, events: List[EnrichedEvent]) -> Dict[str, List[EnrichedEvent]]:
        """Group events by malware family"""
        groups = defaultdict(list)
        
        for event in events:
            family = event.malware_family or 'unknown'
            groups[family.lower()].append(event)
        
        return groups
    
    def _group_by_attack_vector(self, events: List[EnrichedEvent]) -> Dict[str, List[EnrichedEvent]]:
        """Group events by attack vector"""
        groups = defaultdict(list)
        
        for event in events:
            vector = event.attack_vector or 'unknown'
            groups[vector.lower()].append(event)
        
        return groups
    
    def _create_pattern_from_group(self, group_name: str, events: List[EnrichedEvent], 
                                   group_type: str) -> ThreatPattern:
        """Create pattern from event group"""
        if not events:
            return None
        
        # Collect common attributes
        all_ttps = []
        all_iocs = []
        all_assets = []
        severities = []
        
        for event in events:
            all_ttps.extend(event.ttps)
            all_iocs.extend(event.iocs)
            all_assets.extend(event.affected_assets)
            severities.append(event.original_event.severity)
        
        # Find most common
        ttp_counts = defaultdict(int)
        for ttp in all_ttps:
            ttp_counts[ttp] += 1
        common_ttps = [ttp for ttp, count in sorted(ttp_counts.items(), 
                                                     key=lambda x: x[1], 
                                                     reverse=True)][:5]
        
        # Unique IOCs (limit to avoid huge patterns)
        unique_iocs = []
        seen = set()
        for ioc in all_iocs:
            key = f"{ioc.get('type')}:{ioc.get('value')}"
            if key not in seen:
                unique_iocs.append(ioc)
                seen.add(key)
                if len(unique_iocs) >= 20:
                    break
        
        # Unique assets
        unique_assets = list(set(all_assets))
        
        # Calculate severity (highest in group)
        max_severity = max(severities) if severities else SeverityLevel.MEDIUM
        
        # Generate pattern name
        if group_type == 'ttp':
            pattern_name = f"TTP-Pattern-{group_name.split('-')[0] if '-' in group_name else group_name}"
        elif group_type == 'malware':
            pattern_name = f"Malware-{group_name.title()}"
        elif group_type == 'vector':
            pattern_name = f"Attack-{group_name.title()}"
        else:
            pattern_name = f"Pattern-{group_name}"
        
        # Description
        description = f"Pattern identified: {len(events)} events share "
        if group_type == 'ttp':
            description += f"common TTP {common_ttps[0] if common_ttps else 'N/A'}"
        elif group_type == 'malware':
            description += f"malware family '{group_name}'"
        elif group_type == 'vector':
            description += f"attack vector '{group_name}'"
        
        # Timestamps
        timestamps = [e.original_event.timestamp for e in events]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        
        # Calculate confidence based on group size and data quality
        confidence = min(0.5 + (len(events) * 0.1), 0.95)
        
        pattern = ThreatPattern(
            pattern_id=self._generate_pattern_id(pattern_name + str(first_seen)),
            pattern_name=pattern_name,
            description=description,
            event_ids=[e.event_id for e in events],
            common_ttps=common_ttps,
            common_iocs=unique_iocs,
            affected_systems=unique_assets,
            first_seen=first_seen,
            last_seen=last_seen,
            event_count=len(events),
            confidence=confidence,
            severity=max_severity
        )
        
        return pattern
    
    async def discover_patterns(self, enriched_events: List[EnrichedEvent]) -> List[ThreatPattern]:
        """Discover patterns from enriched events"""
        if not enriched_events:
            return []
        
        self._log("discover_patterns", f"Analyzing {len(enriched_events)} events for patterns")
        
        patterns = []
        
        # Strategy 1: Group by TTPs
        ttp_groups = self._group_by_ttps(enriched_events)
        for group_name, group_events in ttp_groups.items():
            if len(group_events) >= config.MIN_PATTERN_EVENTS and group_name != 'unknown':
                pattern = self._create_pattern_from_group(group_name, group_events, 'ttp')
                if pattern:
                    patterns.append(pattern)
                    self.discovered_patterns[pattern.pattern_id] = pattern
                    self._log("discover_patterns", 
                             f"Discovered TTP pattern: {pattern.pattern_name} ({len(group_events)} events)",
                             pattern.pattern_id)
        
        # Strategy 2: Group by malware family
        malware_groups = self._group_by_malware(enriched_events)
        for group_name, group_events in malware_groups.items():
            if len(group_events) >= config.MIN_PATTERN_EVENTS and group_name != 'unknown':
                pattern = self._create_pattern_from_group(group_name, group_events, 'malware')
                if pattern:
                    # Check if not duplicate
                    if pattern.pattern_id not in self.discovered_patterns:
                        patterns.append(pattern)
                        self.discovered_patterns[pattern.pattern_id] = pattern
                        self._log("discover_patterns", 
                                 f"Discovered malware pattern: {pattern.pattern_name} ({len(group_events)} events)",
                                 pattern.pattern_id)
        
        # Strategy 3: Group by attack vector
        vector_groups = self._group_by_attack_vector(enriched_events)
        for group_name, group_events in vector_groups.items():
            if len(group_events) >= config.MIN_PATTERN_EVENTS and group_name != 'unknown':
                pattern = self._create_pattern_from_group(group_name, group_events, 'vector')
                if pattern:
                    # Check if not duplicate
                    if pattern.pattern_id not in self.discovered_patterns:
                        patterns.append(pattern)
                        self.discovered_patterns[pattern.pattern_id] = pattern
                        self._log("discover_patterns", 
                                 f"Discovered attack vector pattern: {pattern.pattern_name} ({len(group_events)} events)",
                                 pattern.pattern_id)
        
        self._log("discover_patterns", f"Discovered {len(patterns)} new patterns")
        
        return patterns
    
    def get_all_patterns(self) -> List[ThreatPattern]:
        """Get all discovered patterns"""
        return list(self.discovered_patterns.values())
