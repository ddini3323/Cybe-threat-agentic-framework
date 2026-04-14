"""
Agent 1: Ingestion & Normalization Agent
Reads CTI feeds and normalizes them into common schema
"""
import os
import json
import csv
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd
from dateutil import parser as date_parser
import httpx

from models import ThreatEvent, ThreatType, SeverityLevel, AgentLogEntry
import config


class IngestionAgent:
    """Agent responsible for ingesting and normalizing CTI data"""
    
    def __init__(self):
        self.name = "IngestionAgent"
        self.processed_files = set()
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
    
    def _generate_event_id(self, source: str, data: Dict) -> str:
        """Generate unique event ID"""
        key = f"{source}_{json.dumps(data, sort_keys=True)}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    def _parse_timestamp(self, timestamp_str: Any) -> datetime:
        """Parse various timestamp formats"""
        if isinstance(timestamp_str, datetime):
            return timestamp_str
        if pd.isna(timestamp_str) or timestamp_str is None:
            return datetime.now()
        try:
            return date_parser.parse(str(timestamp_str))
        except:
            return datetime.now()
    
    def _detect_threat_type(self, indicator: str) -> ThreatType:
        """Detect threat type from indicator"""
        if not indicator:
            return ThreatType.UNKNOWN
        
        indicator = str(indicator).strip()
        
        # IP address
        if all(part.isdigit() and 0 <= int(part) <= 255 
               for part in indicator.split('.') if part) and indicator.count('.') == 3:
            return ThreatType.IP
        
        # Hash (MD5, SHA1, SHA256)
        if len(indicator) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return ThreatType.HASH
        
        # URL
        if indicator.startswith(('http://', 'https://', 'ftp://')):
            return ThreatType.URL
        
        # CVE
        if indicator.startswith('CVE-'):
            return ThreatType.CVE
        
        # Email
        if '@' in indicator and '.' in indicator.split('@')[-1]:
            return ThreatType.EMAIL
        
        # Domain (rough check)
        if '.' in indicator and not ' ' in indicator:
            return ThreatType.DOMAIN
        
        return ThreatType.UNKNOWN
    
    def _infer_severity(self, description: str, threat_type: ThreatType) -> SeverityLevel:
        """Infer severity from description"""
        if not description:
            return SeverityLevel.MEDIUM
        
        desc_lower = description.lower()
        
        # Critical keywords
        if any(word in desc_lower for word in ['critical', 'ransomware', 'zero-day', 'apt', 'backdoor']):
            return SeverityLevel.CRITICAL
        
        # High keywords
        if any(word in desc_lower for word in ['malware', 'exploit', 'vulnerability', 'attack', 'breach']):
            return SeverityLevel.HIGH
        
        # Low keywords
        if any(word in desc_lower for word in ['scan', 'reconnaisance', 'probe']):
            return SeverityLevel.LOW
        
        return SeverityLevel.MEDIUM
    
    def normalize_csv(self, file_path: Path, source_name: str) -> List[ThreatEvent]:
        """Normalize CSV CTI feed"""
        events = []
        
        try:
            df = pd.read_csv(file_path)
            
            # Common CSV column mappings
            col_mappings = {
                'indicator': ['indicator', 'ioc', 'value', 'observable'],
                'type': ['type', 'ioc_type', 'threat_type', 'indicator_type'],
                'description': ['description', 'comment', 'tags', 'malware'],
                'first_seen': ['first_seen', 'dateadded', 'timestamp', 'date'],
                'last_seen': ['last_seen', 'last_online'],
            }
            
            # Find actual column names
            actual_cols = {}
            for target, candidates in col_mappings.items():
                for col in df.columns:
                    if col.lower() in candidates:
                        actual_cols[target] = col
                        break
            
            for idx, row in df.iterrows():
                # Extract fields
                indicator = row.get(actual_cols.get('indicator')) if 'indicator' in actual_cols else None
                threat_type_str = row.get(actual_cols.get('type')) if 'type' in actual_cols else None
                description = row.get(actual_cols.get('description')) if 'description' in actual_cols else ""
                
                # Build raw text
                raw_text = description if description and not pd.isna(description) else ""
                if not raw_text and indicator:
                    raw_text = f"Threat indicator: {indicator}"
                
                # Detect type
                if threat_type_str and not pd.isna(threat_type_str):
                    try:
                        threat_type = ThreatType[threat_type_str.upper()]
                    except:
                        threat_type = self._detect_threat_type(indicator)
                else:
                    threat_type = self._detect_threat_type(indicator)
                
                # Create event
                event = ThreatEvent(
                    event_id=self._generate_event_id(source_name, row.to_dict()),
                    timestamp=self._parse_timestamp(row.get(actual_cols.get('first_seen')) if 'first_seen' in actual_cols else None),
                    source=source_name,
                    event_type=threat_type,
                    raw_text=raw_text,
                    indicator=str(indicator) if indicator and not pd.isna(indicator) else None,
                    description=str(description) if description and not pd.isna(description) else None,
                    first_seen=self._parse_timestamp(row.get(actual_cols.get('first_seen')) if 'first_seen' in actual_cols else None),
                    last_seen=self._parse_timestamp(row.get(actual_cols.get('last_seen')) if 'last_seen' in actual_cols else None),
                    severity=self._infer_severity(raw_text, threat_type),
                    raw_data=row.to_dict()
                )
                events.append(event)
            
            self._log("normalize_csv", f"Normalized {len(events)} events from {file_path.name}")
            
        except Exception as e:
            self._log("normalize_csv", f"Error processing {file_path.name}: {str(e)}", status="error")
        
        return events
    
    def normalize_json(self, file_path: Path, source_name: str) -> List[ThreatEvent]:
        """Normalize JSON CTI feed"""
        events = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both single object and array
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                raise ValueError("JSON must be object or array")
            
            for item in data:
                # Extract fields (flexible schema)
                raw_text = item.get('raw_text') or item.get('description') or item.get('summary') or json.dumps(item)
                indicator = item.get('indicator') or item.get('ioc') or item.get('value')
                
                # Detect type
                threat_type_str = item.get('type') or item.get('event_type')
                if threat_type_str:
                    try:
                        threat_type = ThreatType[threat_type_str.upper()]
                    except:
                        threat_type = self._detect_threat_type(indicator)
                else:
                    threat_type = self._detect_threat_type(indicator)
                
                event = ThreatEvent(
                    event_id=self._generate_event_id(source_name, item),
                    timestamp=self._parse_timestamp(item.get('timestamp')),
                    source=item.get('source', source_name),
                    event_type=threat_type,
                    raw_text=raw_text,
                    indicator=indicator,
                    description=item.get('description'),
                    first_seen=self._parse_timestamp(item.get('first_seen')),
                    last_seen=self._parse_timestamp(item.get('last_seen')),
                    severity=SeverityLevel(item.get('severity', 2)) if isinstance(item.get('severity'), int) else self._infer_severity(raw_text, threat_type),
                    raw_data=item
                )
                events.append(event)
            
            self._log("normalize_json", f"Normalized {len(events)} events from {file_path.name}")
            
        except Exception as e:
            self._log("normalize_json", f"Error processing {file_path.name}: {str(e)}", status="error")
        
        return events
    
    async def fetch_from_url(self, url: str, source_name: str) -> List[ThreatEvent]:
        """Fetch and normalize CTI feed from URL"""
        events = []
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                # Save to temp file and process
                temp_file = config.INPUT_DIR / f"temp_{hashlib.md5(url.encode()).hexdigest()[:8]}"
                
                if 'json' in response.headers.get('content-type', '').lower():
                    temp_file = temp_file.with_suffix('.json')
                    temp_file.write_text(response.text)
                    events = self.normalize_json(temp_file, source_name)
                else:
                    # Assume CSV
                    temp_file = temp_file.with_suffix('.csv')
                    temp_file.write_text(response.text)
                    events = self.normalize_csv(temp_file, source_name)
                
                # Clean up temp file
                temp_file.unlink(missing_ok=True)
                
                self._log("fetch_from_url", f"Fetched {len(events)} events from {url}")
        
        except Exception as e:
            self._log("fetch_from_url", f"Error fetching {url}: {str(e)}", status="error")
        
        return events
    
    async def ingest_from_directory(self, directory: Path) -> List[ThreatEvent]:
        """Ingest all new files from directory"""
        all_events = []
        
        if not directory.exists():
            return all_events
        
        for file_path in directory.iterdir():
            # Skip if already processed
            file_key = f"{file_path.name}_{file_path.stat().st_mtime}"
            if file_key in self.processed_files:
                continue
            
            if file_path.suffix.lower() == '.csv':
                events = self.normalize_csv(file_path, file_path.stem)
                all_events.extend(events)
                self.processed_files.add(file_key)
            
            elif file_path.suffix.lower() == '.json':
                events = self.normalize_json(file_path, file_path.stem)
                all_events.extend(events)
                self.processed_files.add(file_key)
        
        if all_events:
            self._log("ingest_from_directory", f"Ingested {len(all_events)} total events from {len([f for f in directory.iterdir()])} files")
        
        return all_events
    
    async def ingest_all(self) -> List[ThreatEvent]:
        """Ingest from all configured sources"""
        all_events = []
        
        # Ingest from directory
        dir_events = await self.ingest_from_directory(config.INPUT_DIR)
        all_events.extend(dir_events)
        
        # Ingest from URLs
        for url in config.EXTERNAL_FEEDS:
            url_events = await self.fetch_from_url(url, f"feed_{hashlib.md5(url.encode()).hexdigest()[:8]}")
            all_events.extend(url_events)
        
        return all_events
