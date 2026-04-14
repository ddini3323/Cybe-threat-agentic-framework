"""
Data models and schemas for CTI Agentic System
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class ThreatType(str, Enum):
    """Types of threat indicators"""
    IP = "IP"
    URL = "URL"
    DOMAIN = "Domain"
    HASH = "Hash"
    EMAIL = "Email"
    CVE = "CVE"
    UNKNOWN = "Unknown"


class SeverityLevel(int, Enum):
    """Severity levels for threats"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class DataSource(BaseModel):
    """Represents a CTI data source"""
    name: str
    source_type: str  # "file", "url", "api"
    location: str
    status: str = "active"
    last_polled: Optional[datetime] = None
    events_count: int = 0


class ThreatEvent(BaseModel):
    """Normalized threat event"""
    event_id: str
    timestamp: datetime
    source: str
    event_type: ThreatType = ThreatType.UNKNOWN
    raw_text: str
    indicator: Optional[str] = None  # IP, URL, domain, hash, etc.
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class EnrichedEvent(BaseModel):
    """Event after LLM enrichment"""
    event_id: str
    original_event: ThreatEvent
    
    # Extracted by LLM
    iocs: List[Dict[str, str]] = Field(default_factory=list)  # [{"type": "IP", "value": "1.2.3.4"}]
    cves: List[str] = Field(default_factory=list)  # ["CVE-2023-1234"]
    ttps: List[str] = Field(default_factory=list)  # ["T1059 - Command-Line Interface"]
    affected_assets: List[str] = Field(default_factory=list)  # ["Windows", "Linux"]
    malware_family: Optional[str] = None
    attack_vector: Optional[str] = None
    
    enriched_at: datetime = Field(default_factory=datetime.now)
    enrichment_confidence: float = 0.5  # 0-1


class ThreatPattern(BaseModel):
    """Discovered threat pattern"""
    pattern_id: str
    pattern_name: str
    description: str
    event_ids: List[str]
    
    # Pattern characteristics
    common_ttps: List[str] = Field(default_factory=list)
    common_iocs: List[Dict[str, str]] = Field(default_factory=list)
    affected_systems: List[str] = Field(default_factory=list)
    
    first_seen: datetime
    last_seen: datetime
    event_count: int
    confidence: float = 0.5  # 0-1
    severity: SeverityLevel = SeverityLevel.MEDIUM


class MitigationAction(BaseModel):
    """Mitigation recommendation"""
    mitigation_id: str
    pattern_id: Optional[str] = None  # If for a pattern
    event_id: Optional[str] = None  # If for single event
    
    title: str
    description: str
    steps: List[str]  # Action steps
    sample_rule: Optional[str] = None  # Firewall/SIEM rule
    
    priority: SeverityLevel = SeverityLevel.MEDIUM
    status: str = "under_review"  # "under_review", "applied", "rejected"
    
    generated_at: datetime = Field(default_factory=datetime.now)
    validated: bool = False


class AgentLogEntry(BaseModel):
    """Log entry for agent activity"""
    timestamp: datetime = Field(default_factory=datetime.now)
    agent_name: str
    action: str
    details: str
    event_id: Optional[str] = None
    pattern_id: Optional[str] = None
    mitigation_id: Optional[str] = None
    status: str = "success"  # "success", "error", "warning"


class SystemStats(BaseModel):
    """System statistics for dashboard"""
    total_events: int = 0
    total_patterns: int = 0
    total_mitigations: int = 0
    active_sources: int = 0
    last_update: datetime = Field(default_factory=datetime.now)
    
    events_by_severity: Dict[str, int] = Field(default_factory=dict)
    events_by_type: Dict[str, int] = Field(default_factory=dict)
    patterns_by_severity: Dict[str, int] = Field(default_factory=dict)
