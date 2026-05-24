"""
Real-Time Threat Intelligence Feed Streamer
Connects to free, public CTI feeds and streams live threat data into the pipeline.

Supported feeds (no API key required):
  1. Mastodon Local (infosec.exchange)        — Security community public timeline
  2. Mastodon #threatintel (infosec.exchange) — Tagged threat intelligence posts
  3. Mastodon #ioc (infosec.exchange)         — Tagged IOC posts
"""
import asyncio
import hashlib
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import List, Dict, Optional

import httpx

from models import ThreatEvent, ThreatType, SeverityLevel


# ── Feed definitions ──────────────────────────────────────────────────

FEEDS = {
    "mastodon_local": {
        "name": "Mastodon Local (infosec.exchange)",
        "url": "https://infosec.exchange/api/v1/timelines/public?local=true&limit=40",
        "type": "mastodon_api",
        "interval": 120,
        "description": "Local public timeline \u2014 security researchers sharing IOCs, advisories, incidents",
    },
    "mastodon_threatintel": {
        "name": "Mastodon #threatintel (infosec.exchange)",
        "url": "https://infosec.exchange/api/v1/timelines/tag/threatintel?limit=40",
        "type": "mastodon_api",
        "interval": 180,
        "description": "#threatintel tagged posts \u2014 malware families, C2 infrastructure, TTPs",
    },
    "mastodon_ioc": {
        "name": "Mastodon #ioc (infosec.exchange)",
        "url": "https://infosec.exchange/api/v1/timelines/tag/ioc?limit=40",
        "type": "mastodon_api",
        "interval": 300,
        "description": "#ioc tagged posts \u2014 indicators of compromise: IPs, hashes, domains, URLs",
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


def _severity_from_text(text: str) -> SeverityLevel:
    t = text.lower()
    if any(w in t for w in ["ransomware", "apt", "c2", "command and control", "cobalt strike",
                             "emotet", "trickbot", "zero-day", "0day", "critical"]):
        return SeverityLevel.CRITICAL
    if any(w in t for w in ["trojan", "rat", "botnet", "stealer", "exploit",
                             "backdoor", "malware", "rootkit", "keylogger"]):
        return SeverityLevel.HIGH
    if any(w in t for w in ["phishing", "miner", "dropper", "ioc", "indicator",
                             "threat", "suspicious", "vulnerability"]):
        return SeverityLevel.HIGH
    return SeverityLevel.MEDIUM


# ── HTML stripper & IOC patterns ──────────────────────────────────────

class _HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts: List[str] = []

    def handle_data(self, data: str):
        self._parts.append(data)

    def get_text(self) -> str:
        return ' '.join(self._parts).strip()


def _strip_html(html: str) -> str:
    s = _HTMLStripper()
    s.feed(html or '')
    return s.get_text()


def _refang(text: str) -> str:
    """Normalize defanged IOCs written by security researchers."""
    text = re.sub(r'hxxps?://', lambda m: m.group().replace('xx', 'tt'), text, flags=re.I)
    text = re.sub(r'\[\.\]|\(\?\.\)|\[dot\]', '.', text, flags=re.I)
    text = re.sub(r'\(\.\)', '.', text)
    return text


_RE_URL    = re.compile(r'https?://[^\s<>"\[\]]{6,}', re.I)
_RE_IP     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_SHA256 = re.compile(r'\b[a-f0-9]{64}\b', re.I)
_RE_SHA1   = re.compile(r'\b[a-f0-9]{40}\b', re.I)
_RE_MD5    = re.compile(r'\b[a-f0-9]{32}\b', re.I)


# ── Mastodon parser ───────────────────────────────────────────────────

_FEED_SOURCE_NAMES = {
    "mastodon_local":       "Mastodon Local",
    "mastodon_threatintel": "Mastodon #threatintel",
    "mastodon_ioc":         "Mastodon #ioc",
}


def _parse_mastodon(data, feed_key: str) -> List[ThreatEvent]:
    """Parse a Mastodon API JSON response (list of status objects)."""
    if not isinstance(data, list):
        return []

    source_name = _FEED_SOURCE_NAMES.get(feed_key, f'Mastodon ({feed_key})')
    events: List[ThreatEvent] = []

    for status in data:
        if not isinstance(status, dict):
            continue
        post_id = str(status.get('id', '')).strip()
        if not post_id:
            continue

        raw_html = status.get('content', '')
        plain = _strip_html(raw_html)
        if not plain or len(plain) < 20:
            continue

        refanged = _refang(plain)

        # Extract primary indicator (prefer URL > hash > IP)
        urls   = _RE_URL.findall(refanged)
        hashes = _RE_SHA256.findall(refanged) or _RE_SHA1.findall(refanged) or _RE_MD5.findall(refanged)
        ips    = _RE_IP.findall(refanged)

        if urls:
            indicator  = urls[0]
            event_type = ThreatType.URL
        elif hashes:
            indicator  = hashes[0]
            event_type = ThreatType.HASH
        elif ips:
            indicator  = ips[0]
            event_type = ThreatType.IP
        else:
            indicator  = post_id
            event_type = ThreatType.UNKNOWN

        tags   = [t.get('name', '') for t in status.get('tags', []) if t.get('name')]
        author = status.get('account', {}).get('acct', 'unknown')
        post_url = status.get('url', '')

        summary = plain[:300]
        desc = f'[{source_name}] @{author}: {summary}'

        events.append(ThreatEvent(
            event_id=_event_id(feed_key, post_id),
            timestamp=datetime.now(timezone.utc),
            source=source_name,
            event_type=event_type,
            raw_text=desc,
            indicator=indicator,
            description=desc,
            severity=_severity_from_text(plain + ' ' + ' '.join(tags)),
            raw_data={
                'feed': feed_key,
                'tags': tags,
                'author': author,
                'post_url': post_url,
                'iocs_found': {
                    'urls': urls[:5],
                    'hashes': hashes[:5],
                    'ips': ips[:5],
                },
            },
        ))
        if len(events) >= 25:
            break

    return events


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
        self._paused = False
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
        self._paused = False
        for key in self.enabled_feeds:
            task = asyncio.create_task(self._poll_loop(key))
            self._tasks.append(task)

    def stop(self):
        self._running = False
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()

    def pause(self):
        """Pause streaming so a user-submitted event gets immediate attention."""
        if not self._paused:
            self._paused = True
            for t in self._tasks:
                t.cancel()
            self._tasks.clear()
            print("  [feeds] Streaming paused for user submission")

    def resume(self):
        """Resume streaming after user-submitted event processing completes."""
        if self._running and self._paused:
            self._paused = False
            for key in self.enabled_feeds:
                task = asyncio.create_task(self._poll_loop(key))
                self._tasks.append(task)
            print("  [feeds] Streaming resumed")

    @property
    def is_paused(self) -> bool:
        return self._paused

    def get_status(self) -> dict:
        return {
            "streaming": self._running,
            "paused": self._paused,
            "total_ingested": self.total_ingested,
            "feeds": self.feed_status,
        }

    # ── internal ──────────────────────────────────────────────────────

    async def _poll_loop(self, feed_key: str):
        meta = FEEDS[feed_key]
        interval = meta["interval"]
        fs = self.feed_status[feed_key]

        # stagger startup so feeds don't all fire at once
        await asyncio.sleep({"mastodon_local": 2, "mastodon_threatintel": 5, "mastodon_ioc": 8}.get(feed_key, 2))

        while self._running:
            try:
                fs["status"] = "polling"
                events = await self._fetch(feed_key)
                new_events = [e for e in events if e.event_id not in self.seen_ids]
                for e in new_events:
                    self.seen_ids.add(e.event_id)

                if new_events:
                    # Feed events go to events list for display only.
                    # pending_events is reserved for user-submitted live input so
                    # it is not crowded out by high-volume streaming feeds.
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
        headers = {"User-Agent": "CTI-Agentic-System/1.0 (threat intelligence aggregator)"}

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
            r = await client.get(meta["url"])
            r.raise_for_status()
            if meta["type"] == "mastodon_api":
                return _parse_mastodon(r.json(), key)

        return []
