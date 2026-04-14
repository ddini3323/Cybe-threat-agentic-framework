"""
Real-Time Threat Intelligence Feed Streamer
Connects to free, public CTI feeds and streams live threat data into the pipeline.

Supported feeds (no API key required):
  1. URLhaus (abuse.ch)       — Live malicious URLs
  2. ThreatFox (abuse.ch)     — Live IOCs (IPs, domains, URLs, hashes)
  3. Feodo Tracker (abuse.ch) — Botnet C2 servers
"""
import asyncio
import csv
import hashlib
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional

import httpx

from models import ThreatEvent, ThreatType, SeverityLevel


# ── Feed definitions ──────────────────────────────────────────────────

FEEDS = {
    "urlhaus": {
        "name": "URLhaus (abuse.ch)",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "csv_download",
        "interval": 120,
        "description": "Live malicious URLs \u2014 malware distribution, phishing, exploit kits",
    },
    "threatfox": {
        "name": "ThreatFox (abuse.ch)",
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "type": "csv_download",
        "interval": 180,
        "description": "Live IOCs \u2014 C2 IPs, malware hashes, phishing domains",
    },
    "feodo": {
        "name": "Feodo Tracker (abuse.ch)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "text_list",
        "interval": 300,
        "description": "Botnet C2 server IPs (Dridex, Emotet, TrickBot, QakBot)",
    },
}


# ── Helpers ───────────────────────────────────────────────────────────

def _event_id(source: str, indicator: str) -> str:
    raw = f"{source}:{indicator}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _detect_type(indicator: str) -> ThreatType:
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', indicator):
        return ThreatType.IP
    if re.match(r'^https?://', indicator, re.I):
        return ThreatType.URL
    if re.match(r'^[a-f0-9]{32,64}$', indicator, re.I):
        return ThreatType.HASH
    if '.' in indicator and not indicator.startswith('http'):
        return ThreatType.DOMAIN
    return ThreatType.UNKNOWN


def _severity_from_tags(tags: list, threat_type: str = "") -> SeverityLevel:
    text = " ".join(tags).lower() + " " + threat_type.lower()
    if any(w in text for w in ["ransomware", "c2", "apt", "cobalt", "emotet", "trickbot"]):
        return SeverityLevel.CRITICAL
    if any(w in text for w in ["trojan", "rat", "botnet", "stealer", "exploit"]):
        return SeverityLevel.HIGH
    if any(w in text for w in ["phishing", "miner", "dropper"]):
        return SeverityLevel.HIGH
    return SeverityLevel.MEDIUM


# ── Per-feed parsers ──────────────────────────────────────────────────

def _parse_urlhaus(text_or_data) -> List[ThreatEvent]:
    """Parse URLhaus CSV download.
    Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    """
    if isinstance(text_or_data, dict):
        text = ""
    else:
        text = text_or_data
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if len(row) < 7 or row[0] == 'id':
            continue
        url = row[2].strip('"')
        if not url:
            continue
        eid = _event_id('urlhaus', url)
        status = row[3].strip('"')
        threat = row[5].strip('"')
        tags = [t.strip() for t in row[6].strip('"').split(',') if t.strip()]
        host = ''
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ''
        except Exception:
            pass

        desc_parts = []
        if threat:
            desc_parts.append(f'Threat: {threat}.')
        if tags:
            desc_parts.append(f'Tags: {", ".join(tags)}.')
        if host:
            desc_parts.append(f'Host: {host}.')
        if status:
            desc_parts.append(f'Status: {status}.')

        events.append(ThreatEvent(
            event_id=eid,
            timestamp=datetime.now(timezone.utc),
            source='URLhaus',
            event_type=ThreatType.URL,
            raw_text=f'[URLhaus] Malicious URL: {url}. {" ".join(desc_parts)}',
            indicator=url,
            description=' '.join(desc_parts) or 'Malicious URL reported to URLhaus',
            severity=_severity_from_tags(tags, threat),
            raw_data={'feed': 'urlhaus', 'tags': tags, 'threat': threat, 'host': host},
        ))
        if len(events) >= 25:
            break
    return events


def _parse_threatfox(text_or_data) -> List[ThreatEvent]:
    """Parse ThreatFox CSV export.
    Columns: first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type,
             fk_malware, malware_alias, malware_printable, last_seen_utc,
             confidence_level, reference, tags, anonymous, reporter
    """
    if isinstance(text_or_data, dict):
        text = ""
    else:
        text = text_or_data
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if len(row) < 10 or row[0] == 'first_seen_utc':
            continue
        ioc_value = row[2].strip('"').strip()
        if not ioc_value:
            continue
        eid = _event_id('threatfox', ioc_value)
        ioc_type = row[3].strip('"').strip()
        threat_type = row[4].strip('"').strip()
        malware = row[7].strip('"').strip() if len(row) > 7 else ''
        confidence = row[9].strip('"').strip() if len(row) > 9 else '50'
        tags_str = row[11].strip('"').strip() if len(row) > 11 else ''
        tags = [t.strip() for t in tags_str.split(',') if t.strip()]

        desc = f'[ThreatFox] {threat_type}: {ioc_value}'
        if malware:
            desc += f' - Malware: {malware}'
        if tags:
            desc += f' - Tags: {", ".join(tags)}'

        events.append(ThreatEvent(
            event_id=eid,
            timestamp=datetime.now(timezone.utc),
            source='ThreatFox',
            event_type=_detect_type(ioc_value),
            raw_text=desc,
            indicator=ioc_value,
            description=desc,
            severity=_severity_from_tags(tags + [malware, threat_type]),
            raw_data={'feed': 'threatfox', 'malware': malware,
                       'threat_type': threat_type, 'confidence': confidence},
        ))
        if len(events) >= 25:
            break
    return events


def _parse_feodo(text: str) -> List[ThreatEvent]:
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split(",")[0].strip()            # some formats have CSV
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            continue
        eid = _event_id("feodo", ip)
        events.append(ThreatEvent(
            event_id=eid,
            timestamp=datetime.now(timezone.utc),
            source="Feodo Tracker",
            event_type=ThreatType.IP,
            raw_text=f"[Feodo Tracker] Botnet C2 server IP: {ip}. "
                     f"Known command-and-control infrastructure for banking trojans "
                     f"(Dridex, Emotet, TrickBot, QakBot).",
            indicator=ip,
            description="Botnet C2 IP on Feodo recommended blocklist",
            severity=SeverityLevel.CRITICAL,
            raw_data={"feed": "feodo"},
        ))
    return events[:25]                              # cap per poll


# ── Main streamer class ──────────────────────────────────────────────

class FeedStreamer:
    """Polls free threat-intel feeds and pushes events into the pipeline."""

    def __init__(self, state_dict: dict, enabled_feeds: Optional[List[str]] = None):
        self.state = state_dict
        self.seen_ids: set = set()
        self.enabled_feeds = enabled_feeds or list(FEEDS.keys())
        self.feed_status: Dict[str, dict] = {}
        self.total_ingested = 0
        self._running = False
        self._tasks: List[asyncio.Task] = []

        for key in self.enabled_feeds:
            meta = FEEDS[key]
            self.feed_status[key] = {
                "name": meta["name"],
                "description": meta["description"],
                "url": meta["url"],
                "interval": meta["interval"],
                "status": "waiting",        # waiting | polling | active | error
                "last_poll": None,
                "events_fetched": 0,
                "last_error": None,
            }

    # ── public API ────────────────────────────────────────────────────

    def start(self):
        """Launch one async task per feed (call from an already-running loop)."""
        self._running = True
        for key in self.enabled_feeds:
            task = asyncio.create_task(self._poll_loop(key))
            self._tasks.append(task)

    def stop(self):
        self._running = False
        for t in self._tasks:
            t.cancel()

    def get_status(self) -> dict:
        return {
            "streaming": self._running,
            "total_ingested": self.total_ingested,
            "feeds": self.feed_status,
        }

    # ── internal ──────────────────────────────────────────────────────

    async def _poll_loop(self, feed_key: str):
        meta = FEEDS[feed_key]
        interval = meta["interval"]
        fs = self.feed_status[feed_key]

        # stagger startup so feeds don't all fire at once
        await asyncio.sleep({"urlhaus": 2, "threatfox": 5, "feodo": 8}.get(feed_key, 2))

        while self._running:
            try:
                fs["status"] = "polling"
                events = await self._fetch(feed_key)
                new_events = [e for e in events if e.event_id not in self.seen_ids]
                for e in new_events:
                    self.seen_ids.add(e.event_id)

                if new_events:
                    # push into the pending queue (same queue as live-input page)
                    self.state.setdefault('pending_events', []).extend(new_events)
                    self.state.setdefault('events', []).extend(new_events)
                    self.total_ingested += len(new_events)
                    fs["events_fetched"] += len(new_events)
                    print(f"  📡 [{meta['name']}] +{len(new_events)} new events")

                fs["status"] = "active"
                fs["last_poll"] = datetime.now(timezone.utc).isoformat()
                fs["last_error"] = None

            except Exception as exc:
                fs["status"] = "error"
                fs["last_error"] = str(exc)[:200]
                print(f"  ⚠ [{meta['name']}] Error: {exc}")

            await asyncio.sleep(interval)

    async def _fetch(self, key: str) -> List[ThreatEvent]:
        meta = FEEDS[key]
        timeout = httpx.Timeout(30.0, connect=10.0)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            if key == "urlhaus":
                r = await client.get(meta["url"])
                r.raise_for_status()
                return _parse_urlhaus(r.text)

            elif key == "threatfox":
                r = await client.get(meta["url"])
                r.raise_for_status()
                return _parse_threatfox(r.text)

            elif key == "feodo":
                r = await client.get(meta["url"])
                r.raise_for_status()
                return _parse_feodo(r.text)

        return []
