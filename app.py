"""
FastAPI Web Server
Provides REST API and serves dashboard
"""
import json
import csv
import io
import hashlib
from datetime import datetime
from typing import List
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from models import (ThreatEvent, EnrichedEvent, ThreatPattern, 
                    MitigationAction, AgentLogEntry, SystemStats, DataSource,
                    ThreatType, SeverityLevel)
import config


app = FastAPI(title="CTI Agentic System", version="1.0.0")


# Inline SVG favicon (shield icon)
_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
    '<text y="80" font-size="80">🛡️</text></svg>'
)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state (will be populated by main.py)
state = {
    'events': [],
    'enriched_events': [],
    'patterns': [],
    'mitigations': [],
    'agent_logs': [],
    'data_sources': [],
    'stats': SystemStats(),
    'pending_events': [],  # Real-time submitted events awaiting pipeline processing
    'current_pipeline_step': 0,  # 0=idle, 1-5=which agent is currently running
    'pipeline_status': 'idle',  # idle, running
    'feed_streamer': None,  # Set by main.py when streaming starts
}


def update_stats():
    """Update system statistics"""
    state['stats'].total_events = len(state['events'])
    state['stats'].total_patterns = len(state['patterns'])
    state['stats'].total_mitigations = len(state['mitigations'])
    state['stats'].active_sources = len([s for s in state['data_sources'] if s.status == 'active'])
    state['stats'].last_update = datetime.now()
    
    # Events by severity
    sev_counts = {}
    for event in state['events']:
        sev = event.severity.name
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    state['stats'].events_by_severity = sev_counts
    
    # Events by type
    type_counts = {}
    for event in state['events']:
        etype = event.event_type.value
        type_counts[etype] = type_counts.get(etype, 0) + 1
    state['stats'].events_by_type = type_counts
    
    # Patterns by severity
    pat_sev = {}
    for pattern in state['patterns']:
        sev = pattern.severity.name
        pat_sev[sev] = pat_sev.get(sev, 0) + 1
    state['stats'].patterns_by_severity = pat_sev


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve pipeline overview dashboard"""
    dashboard_path = config.STATIC_DIR / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(dashboard_path)
    return HTMLResponse("<h1>CTI Agentic System</h1><p>Dashboard loading...</p>")


@app.get("/ingestion", response_class=HTMLResponse)
async def ingestion_page():
    """Serve Ingestion Agent page"""
    return FileResponse(config.STATIC_DIR / "ingestion.html")


@app.get("/enrichment", response_class=HTMLResponse)
async def enrichment_page():
    """Serve Enrichment Agent page"""
    return FileResponse(config.STATIC_DIR / "enrichment.html")


@app.get("/patterns", response_class=HTMLResponse)
async def patterns_page():
    """Serve Pattern Discovery Agent page"""
    return FileResponse(config.STATIC_DIR / "patterns.html")


@app.get("/mitigations", response_class=HTMLResponse)
async def mitigations_page():
    """Serve Mitigation & Validation page"""
    return FileResponse(config.STATIC_DIR / "mitigations.html")


@app.get("/flow-tracker", response_class=HTMLResponse)
async def flow_tracker_page():
    """Serve Flow Tracker page"""
    return FileResponse(config.STATIC_DIR / "flow-tracker.html")


@app.get("/live-input", response_class=HTMLResponse)
async def live_input_page():
    """Serve Live Input page"""
    return FileResponse(config.STATIC_DIR / "live-input.html")


@app.get("/feeds", response_class=HTMLResponse)
async def feeds_page():
    """Serve Streaming Feeds page"""
    return FileResponse(config.STATIC_DIR / "feeds.html")


@app.get("/api/feeds")
async def get_feeds_status():
    """Get status of all streaming feeds"""
    streamer = state.get('feed_streamer')
    if streamer:
        return streamer.get_status()
    return {"streaming": False, "total_ingested": 0, "feeds": {}}


def _generate_event_id(source: str, data: str) -> str:
    key = f"{source}_{data}_{datetime.now().isoformat()}"
    return hashlib.md5(key.encode()).hexdigest()[:16]


def _detect_threat_type(indicator: str) -> ThreatType:
    if not indicator:
        return ThreatType.UNKNOWN
    indicator = indicator.strip()
    if all(part.isdigit() and 0 <= int(part) <= 255 for part in indicator.split('.') if part) and indicator.count('.') == 3:
        return ThreatType.IP
    if len(indicator) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in indicator):
        return ThreatType.HASH
    if indicator.startswith(('http://', 'https://')):
        return ThreatType.URL
    if indicator.startswith('CVE-'):
        return ThreatType.CVE
    if '@' in indicator and '.' in indicator.split('@')[-1]:
        return ThreatType.EMAIL
    if '.' in indicator and ' ' not in indicator:
        return ThreatType.DOMAIN
    return ThreatType.UNKNOWN


def _infer_severity(text: str) -> SeverityLevel:
    if not text:
        return SeverityLevel.MEDIUM
    t = text.lower()
    if any(w in t for w in ['critical', 'ransomware', 'zero-day', 'apt', 'backdoor', 'emergency']):
        return SeverityLevel.CRITICAL
    if any(w in t for w in ['malware', 'exploit', 'vulnerability', 'attack', 'breach', 'c2', 'botnet']):
        return SeverityLevel.HIGH
    if any(w in t for w in ['scan', 'reconnaissance', 'probe', 'info']):
        return SeverityLevel.LOW
    return SeverityLevel.MEDIUM


@app.post("/api/ingest/json")
async def ingest_json(body: dict):
    """Ingest a single JSON threat event in real-time"""
    try:
        raw_text = body.get('raw_text') or body.get('description') or body.get('summary') or json.dumps(body)
        indicator = body.get('indicator') or body.get('ioc') or body.get('value') or ''
        threat_type_str = body.get('type') or body.get('event_type')
        try:
            threat_type = ThreatType[threat_type_str.upper()] if threat_type_str else _detect_threat_type(indicator)
        except (KeyError, AttributeError):
            threat_type = _detect_threat_type(indicator)
        sev = body.get('severity')
        severity = SeverityLevel(sev) if isinstance(sev, int) and 1 <= sev <= 5 else _infer_severity(raw_text)
        event = ThreatEvent(
            event_id=_generate_event_id('live-json', raw_text),
            timestamp=datetime.now(),
            source=body.get('source', 'Live Input (JSON)'),
            event_type=threat_type,
            raw_text=raw_text,
            indicator=indicator if indicator else None,
            description=body.get('description'),
            severity=severity,
            raw_data=body
        )
        state['events'].append(event)
        state['pending_events'].append(event)
        return {'success': True, 'event_id': event.event_id, 'message': 'Event queued for pipeline processing'}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON input: {str(e)}")


@app.post("/api/ingest/csv")
async def ingest_csv(body: dict):
    """Ingest CSV text data in real-time"""
    csv_text = body.get('csv_data', '')
    if not csv_text.strip():
        raise HTTPException(status_code=400, detail="No CSV data provided")
    try:
        reader = csv.DictReader(io.StringIO(csv_text))
        events = []
        for row in reader:
            indicator = row.get('indicator') or row.get('ioc') or row.get('value') or ''
            description = row.get('description') or row.get('comment') or row.get('tags') or ''
            raw_text = description if description else f"Threat indicator: {indicator}"
            threat_type_str = row.get('type') or row.get('threat_type')
            try:
                threat_type = ThreatType[threat_type_str.upper()] if threat_type_str else _detect_threat_type(indicator)
            except (KeyError, AttributeError):
                threat_type = _detect_threat_type(indicator)
            event = ThreatEvent(
                event_id=_generate_event_id('live-csv', raw_text + indicator),
                timestamp=datetime.now(),
                source='Live Input (CSV)',
                event_type=threat_type,
                raw_text=raw_text,
                indicator=indicator if indicator else None,
                description=description if description else None,
                severity=_infer_severity(raw_text),
                raw_data=dict(row)
            )
            events.append(event)
        state['events'].extend(events)
        state['pending_events'].extend(events)
        return {'success': True, 'events_count': len(events), 'message': f'{len(events)} events queued for pipeline processing'}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV parse error: {str(e)}")


@app.post("/api/ingest/text")
async def ingest_text(body: dict):
    """Ingest free-text threat description in real-time"""
    text = body.get('text', '').strip()
    if not text:
        raise HTTPException(status_code=400, detail="No text provided")
    # Try to extract an indicator from the text
    indicator = None
    import re
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if ip_match:
        indicator = ip_match.group()
    else:
        url_match = re.search(r'https?://[^\s]+', text)
        if url_match:
            indicator = url_match.group()
        else:
            domain_match = re.search(r'\b[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+\b', text)
            if domain_match:
                indicator = domain_match.group()
    threat_type = _detect_threat_type(indicator) if indicator else ThreatType.UNKNOWN
    event = ThreatEvent(
        event_id=_generate_event_id('live-text', text),
        timestamp=datetime.now(),
        source='Live Input (Text)',
        event_type=threat_type,
        raw_text=text,
        indicator=indicator,
        description=text[:200],
        severity=_infer_severity(text),
        raw_data={'text': text}
    )
    state['events'].append(event)
    state['pending_events'].append(event)
    return {'success': True, 'event_id': event.event_id, 'indicator': indicator, 'severity': event.severity.name, 'message': 'Event queued for pipeline processing'}


@app.post("/api/ingest/file")
async def ingest_file(file: UploadFile = File(...)):
    """Upload a CSV or JSON file for real-time ingestion"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    ext = Path(file.filename).suffix.lower()
    if ext not in ['.json', '.csv']:
        raise HTTPException(status_code=400, detail="Only .json and .csv files are supported")
    content = (await file.read()).decode('utf-8')
    # Save to input directory so the ingestion agent picks it up on next cycle
    dest = config.INPUT_DIR / f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    dest.write_text(content, encoding='utf-8')
    return {'success': True, 'filename': file.filename, 'saved_as': dest.name, 'message': 'File saved. Will be processed in the next pipeline cycle.'}


@app.get("/api/pending")
async def get_pending():
    """Get count of events waiting for pipeline processing"""
    return {'pending_count': len(state['pending_events'])}


@app.get("/api/stats")
async def get_stats():
    """Get system statistics"""
    update_stats()
    return state['stats']


@app.get("/api/sources")
async def get_sources() -> List[DataSource]:
    """Get data sources"""
    return state['data_sources']


@app.get("/api/events")
async def get_events(limit: int = 50) -> List[ThreatEvent]:
    """Get recent threat events"""
    return state['events'][-limit:]


@app.get("/api/events/{event_id}")
async def get_event(event_id: str):
    """Get specific event"""
    for event in state['events']:
        if event.event_id == event_id:
            return event
    raise HTTPException(status_code=404, detail="Event not found")


@app.get("/api/enriched-events")
async def get_enriched_events(limit: int = 50) -> List[EnrichedEvent]:
    """Get enriched events"""
    return state['enriched_events'][-limit:]


@app.get("/api/patterns")
async def get_patterns() -> List[ThreatPattern]:
    """Get all patterns"""
    return state['patterns']


@app.get("/api/patterns/{pattern_id}")
async def get_pattern(pattern_id: str):
    """Get specific pattern with details"""
    for pattern in state['patterns']:
        if pattern.pattern_id == pattern_id:
            # Get associated events
            pattern_events = [e for e in state['enriched_events'] 
                            if e.event_id in pattern.event_ids]
            
            return {
                'pattern': pattern,
                'events': pattern_events
            }
    raise HTTPException(status_code=404, detail="Pattern not found")


@app.get("/api/mitigations")
async def get_mitigations() -> List[MitigationAction]:
    """Get all mitigations"""
    return state['mitigations']


@app.get("/api/mitigations/{mitigation_id}")
async def get_mitigation(mitigation_id: str):
    """Get specific mitigation"""
    for mitigation in state['mitigations']:
        if mitigation.mitigation_id == mitigation_id:
            return mitigation
    raise HTTPException(status_code=404, detail="Mitigation not found")


@app.post("/api/mitigations/{mitigation_id}/status")
async def update_mitigation_status(mitigation_id: str, body: dict):
    """Update mitigation status"""
    status = body.get('status', '')
    if status not in ['under_review', 'applied', 'rejected', 'approved']:
        raise HTTPException(status_code=400, detail="Invalid status. Must be one of: under_review, applied, rejected, approved")
    
    for mitigation in state['mitigations']:
        if mitigation.mitigation_id == mitigation_id:
            mitigation.status = status
            return {'success': True, 'mitigation': mitigation}
    
    raise HTTPException(status_code=404, detail="Mitigation not found")


@app.get("/api/logs")
async def get_logs(limit: int = 100) -> List[AgentLogEntry]:
    """Get agent activity logs"""
    return state['agent_logs'][-limit:]


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'events_count': len(state['events']),
        'patterns_count': len(state['patterns']),
        'mitigations_count': len(state['mitigations']),
        'current_pipeline_step': state.get('current_pipeline_step', 0),
        'pipeline_status': state.get('pipeline_status', 'idle')
    }


# Save logs endpoint
@app.post("/api/save-logs")
async def save_logs():
    """Save agent logs to file"""
    try:
        log_data = [log.dict() for log in state['agent_logs']]
        
        with open(config.AGENT_LOG_FILE, 'w') as f:
            json.dump(log_data, f, indent=2, default=str)
        
        return {'success': True, 'logs_saved': len(log_data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.WEB_HOST, port=config.WEB_PORT)
