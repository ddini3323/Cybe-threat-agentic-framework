"""
CTI Chatbot Agent
Answers natural language questions about the threat intelligence pipeline.
"""
import re
from typing import List, Dict


class CTIChatbot:
    """Natural language assistant for querying pipeline state."""

    def __init__(self, llm, state: dict):
        self.llm = llm
        self.state = state

    async def respond(self, message: str, history: List[Dict]) -> str:
        import traceback as _tb
        try:
            return await self._respond_inner(message, history)
        except Exception as exc:
            _tb.print_exc()
            raise

    async def _respond_inner(self, message: str, history: List[Dict]) -> str:
        msg = message.strip().lower()

        # --- ID lookup (8–16 hex chars) ---
        id_match = re.search(r'\b([0-9a-f]{8,16})\b', message, re.I)
        if id_match:
            return self._lookup_id(id_match.group(1).lower())

        # --- Keyword-based fast paths ---
        if any(w in msg for w in ['queue', 'pending', 'waiting', 'queued']):
            return self._pending_status()

        if any(w in msg for w in ['complete', 'finished', 'done', 'validated']):
            return self._completed_status()

        if any(w in msg for w in ['running', 'processing', 'active', 'current step']):
            return self._running_status()

        if any(w in msg for w in ['last', 'recent', 'latest', 'just submitted']):
            return self._recent_submission()

        if 'pattern' in msg:
            return self._patterns_status()

        if 'mitigation' in msg or 'recommendation' in msg:
            return self._mitigations_status()

        if any(w in msg for w in ['pipeline', 'status', 'health', 'system', 'feed', 'stream']):
            return self._pipeline_status()

        if any(w in msg for w in ['help', 'what can', 'how do', 'what do you']):
            return self._help()

        # --- LLM fallback ---
        return await self._llm_respond(message, history)

    # ── Pipeline trace ──────────────────────────────────────────────────

    def _get_trace(self, event_id: str) -> dict:
        raw = next((e for e in self.state.get('events', [])
                    if e.event_id == event_id), None)
        enriched = next((e for e in self.state.get('enriched_events', [])
                         if e.event_id == event_id), None)
        cls = next((c for c in self.state.get('classifications', [])
                    if c.event_id == event_id), None)
        mit = next((m for m in self.state.get('mitigations', [])
                    if m.event_id == event_id), None)
        patterns = [p for p in self.state.get('patterns', [])
                    if event_id in p.event_ids]
        validated = bool(mit and mit.validated)

        # Queue position (1-indexed), None if not pending
        pending = self.state.get('pending_events', [])
        queue_pos = next((i + 1 for i, e in enumerate(pending)
                          if e.event_id == event_id), None)

        completed_steps = []
        remaining_steps = []
        all_steps = [
            (1, "Ingest"),
            (2, "Enrich (O1)"),
            (3, "Classify (O2)"),
            (4, "Pattern Discovery"),
            (5, "Mitigate (O3)"),
            (6, "Validate"),
        ]
        if raw:           completed_steps.append(1)
        if enriched:      completed_steps.append(2)
        if cls:           completed_steps.append(3)
        if patterns:      completed_steps.append(4)
        if mit:           completed_steps.append(5)
        if validated:     completed_steps.append(6)
        remaining_steps = [s for s in all_steps if s[0] not in completed_steps]

        if validated:
            stage = "COMPLETE — validated mitigation ready"
        elif mit:
            stage = "Mitigation generated — awaiting validation"
        elif cls:
            stage = "Classified (O2 ✓) — generating mitigations"
        elif enriched:
            stage = "Enriched (O1 ✓) — awaiting classification"
        elif raw and queue_pos:
            stage = f"Ingested — queued at position #{queue_pos}"
        elif raw:
            stage = "Ingested — awaiting next pipeline cycle"
        else:
            stage = "Not found"

        return {
            'found': raw is not None,
            'stage': stage,
            'raw': raw,
            'enriched': enriched,
            'classification': cls,
            'mitigation': mit,
            'patterns': patterns,
            'queue_pos': queue_pos,
            'completed_steps': completed_steps,
            'remaining_steps': remaining_steps,
        }

    def _safe(self, v, default='N/A'):
        """Return str(v) safely, or default if v is None/empty."""
        try:
            return str(v) if v is not None else default
        except Exception:
            return default

    def _safe_join(self, items, limit=4, sep=', '):
        """Join a list of anything into a string safely."""
        try:
            if not items:
                return 'none'
            parts = []
            for x in list(items)[:limit]:
                if isinstance(x, dict):
                    parts.append(x.get('value') or x.get('name') or x.get('id') or str(x))
                else:
                    parts.append(str(x))
            return sep.join(parts) or 'none'
        except Exception:
            return 'N/A'

    def _lookup_id(self, event_id: str) -> str:
        try:
            return self._lookup_id_inner(event_id)
        except Exception as exc:
            import traceback as _tb
            _tb.print_exc()
            return (f"Error building trace for `{event_id}`: {exc}\n"
                    "Try restarting the server if this persists.")

    def _lookup_id_inner(self, event_id: str) -> str:
        trace = self._get_trace(event_id)

        if not trace['found']:
            all_ids = [e.event_id for e in self.state.get('events', [])]
            matches = [eid for eid in all_ids
                       if eid.startswith(event_id) or event_id in eid]
            if not matches:
                total = len(all_ids)
                hint = (f"There are {total} events in the system." if total
                        else "No events have been submitted yet.")
                return (
                    f"No threat found with ID `{event_id}`.\n"
                    f"{hint}\n"
                    "Try: `my last submission` to see the most recent one."
                )
            if len(matches) > 1:
                lines = [f"Multiple threats match `{event_id}`:"]
                lines += [f"  • `{m}`" for m in matches[:6]]
                return "\n".join(lines)
            event_id = matches[0]
            trace = self._get_trace(event_id)

        lines = [f"**Threat `{event_id}`**",
                 f"**Stage: {trace['stage']}**", ""]

        raw = trace['raw']
        if raw:
            try:
                full_text = str(raw.raw_text or raw.description or '')
                display_text = full_text[:300] + ('…' if len(full_text) > 300 else '')
                lines += [
                    "**Original Submission:**",
                    f"  {display_text}",
                    "",
                    f"  Source: {raw.source}  |  Type: {self._safe(raw.event_type.value)}",
                    f"  Severity: **{raw.severity.name}**",
                    f"  Submitted: {raw.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                ]
                if raw.indicator:
                    lines.append(f"  Indicator: `{raw.indicator}`")
                lines.append("")
            except Exception as e:
                lines.append(f"  (raw event data error: {e})")
                lines.append("")

        # Queue & ETA
        qpos = trace['queue_pos']
        pipeline_status = self.state.get('pipeline_status', 'idle')
        try:
            import config as _cfg
            interval = getattr(_cfg, 'POLLING_INTERVAL', 60)
        except Exception:
            interval = 60

        if qpos:
            lines.append("**Queue Status:**")
            lines.append(f"  Position **#{qpos}** in pending queue "
                         f"({qpos - 1} event(s) ahead)")
            if pipeline_status == 'running':
                lines.append("  Pipeline is currently RUNNING — "
                             "this event will start after the current cycle completes")
            else:
                eta_s = (qpos - 1) * 5 + (interval // 2)
                lines.append(f"  Pipeline is IDLE — estimated start: "
                              f"within ~{eta_s}s (next cycle)")
            lines.append("")
        elif trace['remaining_steps']:
            lines.append("**Remaining Pipeline Steps:**")
            for _, name in trace['remaining_steps']:
                lines.append(f"  ⏳ {name}")
            lines.append("")

        if trace['completed_steps']:
            done_names = [n for s, n in [
                (1, "Ingest"), (2, "Enrich O1"), (3, "Classify O2"),
                (4, "Patterns"), (5, "Mitigate O3"), (6, "Validate")
            ] if s in trace['completed_steps']]
            lines.append("**Completed:** " + " → ".join(done_names))
            lines.append("")

        enriched = trace['enriched']
        if enriched:
            try:
                lines += [
                    "**Enrichment (O1) ✓**",
                    f"  Category: {self._safe(enriched.threat_category)}",
                    f"  Attack Stage: {self._safe(enriched.attack_stage)}",
                    f"  Confidence: {enriched.enrichment_confidence:.0%}",
                ]
                if enriched.malware_family:
                    lines.append(f"  Malware: {enriched.malware_family}")
                if enriched.attack_vector:
                    lines.append(f"  Vector: {enriched.attack_vector}")
                ttps = enriched.ttps
                if ttps:
                    lines.append(f"  TTPs: {self._safe_join(ttps, 4)}")
                tactics = enriched.mitre_tactics
                if tactics:
                    lines.append(f"  MITRE Tactics: {self._safe_join(tactics, 3)}")
                if enriched.cves:
                    lines.append(f"  CVEs: {self._safe_join(enriched.cves, 4)}")
                if enriched.iocs:
                    lines.append(f"  IOCs: {self._safe_join(enriched.iocs, 3)}")
                lines.append("")
            except Exception as e:
                lines.append(f"  (enrichment render error: {e})")
                lines.append("")

        cls = trace['classification']
        if cls:
            try:
                lines += [
                    "**Classification (O2) ✓**",
                    f"  Category: {self._safe(cls.threat_category)}",
                    f"  Attack Stage: {self._safe(cls.attack_stage)}",
                    f"  Asset Category: {self._safe(cls.affected_asset_category)}",
                    f"  Confidence: {cls.classification_confidence:.0%}",
                ]
                if cls.severity_justification:
                    lines.append(
                        f"  Why: {str(cls.severity_justification)[:120]}")
                lines.append("")
            except Exception as e:
                lines.append(f"  (classification render error: {e})")
                lines.append("")

        mit = trace['mitigation']
        if mit:
            try:
                d3 = self._safe_join(mit.mitre_d3fend or [])
                steps = list(mit.steps or [])
                steps_preview = '; '.join(str(s) for s in steps[:2])
                lines += [
                    "**Mitigation (O3) ✓**",
                    f"  Title: {self._safe(mit.title)}",
                    f"  Description: {str(mit.description)[:120]}",
                ]
                if steps_preview:
                    lines.append(f"  Steps: {steps_preview[:120]}")
                lines += [
                    f"  D3FEND: {d3}",
                    f"  Validated: {'✓ Yes' if mit.validated else '⏳ Pending'}",
                    f"  Priority: {mit.priority.name}",
                    "",
                ]
            except Exception as e:
                lines.append(f"  (mitigation render error: {e})")
                lines.append("")
        elif trace['completed_steps'] and 2 in trace['completed_steps']:
            lines.append("**Mitigation:** ⏳ Not yet generated")
            lines.append("")

        if trace['patterns']:
            try:
                pat_names = [f"`{p.pattern_id}` ({p.pattern_name})"
                             for p in trace['patterns'][:3]]
                lines.append(f"**Patterns:** linked to "
                             f"{len(trace['patterns'])} — "
                             + ', '.join(pat_names))
            except Exception as e:
                lines.append(f"  (pattern render error: {e})")

        return "\n".join(lines)

    # ── Status helpers ──────────────────────────────────────────────────

    def _pending_status(self) -> str:
        pending = self.state.get('pending_events', [])
        if not pending:
            return (
                "Queue is empty — no events waiting to be processed.\n"
                "Submit a threat via the Live Input page to add one."
            )
        lines = [f"**{len(pending)} event(s) in queue:**"]
        for e in pending[:6]:
            lines.append(
                f"  • `{e.event_id}` — {e.event_type.value} | "
                f"{e.severity.name} | {e.source}"
            )
        if len(pending) > 6:
            lines.append(f"  ...and {len(pending) - 6} more")
        return "\n".join(lines)

    def _running_status(self) -> str:
        step_names = {
            0: 'Idle', 1: 'Ingestion', 2: 'Enrichment (O1)',
            3: 'Pattern Discovery', 4: 'Mitigation (O3)', 5: 'Validation',
        }
        step = self.state.get('current_pipeline_step', 0)
        status = self.state.get('pipeline_status', 'idle')
        paused = self.state.get('pipeline_paused', False)
        total = len(self.state.get('events', []))
        enriched = len(self.state.get('enriched_events', []))
        patterns = len(self.state.get('patterns', []))
        mitigations = len(self.state.get('mitigations', []))

        lines = [
            f"**Pipeline: {status.upper()}" + (" (PAUSED)" if paused else "") + "**",
            f"Current step: {step_names.get(step, str(step))}",
            f"Events seen: {total}  |  Enriched: {enriched}  |  "
            f"Patterns: {patterns}  |  Mitigations: {mitigations}",
        ]

        streamer = self.state.get('feed_streamer')
        if streamer:
            fs = streamer.get_status()
            feed_state = "PAUSED" if streamer.is_paused else "STREAMING"
            lines.append(
                f"Feeds: {feed_state} — {fs['total_ingested']} events collected"
            )
        return "\n".join(lines)

    def _completed_status(self) -> str:
        mitigations = self.state.get('mitigations', [])
        validated = [m for m in mitigations if m.validated]
        if not validated:
            return (
                "No threats have completed the full pipeline yet.\n"
                "Full path: Ingest → Enrich (O1) → Classify (O2) → "
                "Pattern → Mitigate (O3) → Validate."
            )
        lines = [f"**{len(validated)} threat(s) fully processed:**"]
        for m in validated[-6:]:
            lines.append(f"  • `{m.event_id}` — {m.title[:80]}")
        if len(validated) > 6:
            lines.append(f"  ...and {len(validated) - 6} more. See /mitigations.")
        return "\n".join(lines)

    def _recent_submission(self) -> str:
        events = self.state.get('events', [])
        # Only show events the user actually submitted (not Mastodon feed noise)
        user_sources = ('Live Input', 'Instant Submit')
        live = [e for e in events
                if any(s in e.source for s in user_sources)]
        if not live:
            return (
                "No user submissions yet.\n"
                "Use the Live Input page or the ⚡ Instant button to submit a threat."
            )
        target = live[-1]
        return "Most recent submission:\n\n" + self._lookup_id(target.event_id)

    def _patterns_status(self) -> str:
        patterns = self.state.get('patterns', [])
        if not patterns:
            return (
                "No patterns discovered yet.\n"
                "Patterns are identified after multiple related events are enriched."
            )
        lines = [f"**{len(patterns)} pattern(s) discovered:**"]
        for p in patterns[-5:]:
            lines.append(
                f"  • `{p.pattern_id}` — {p.pattern_name} | "
                f"{p.severity.name} | {len(p.event_ids)} event(s) | "
                f"{p.description[:80]}"
            )
        return "\n".join(lines)

    def _mitigations_status(self) -> str:
        mits = self.state.get('mitigations', [])
        if not mits:
            return (
                "No mitigations generated yet.\n"
                "They appear after pattern discovery completes."
            )
        validated = sum(1 for m in mits if m.validated)
        lines = [f"**{len(mits)} mitigation(s), {validated} validated:**"]
        for m in mits[-5:]:
            tick = "✓" if m.validated else "⏳"
            lines.append(f"  {tick} `{m.event_id}` — {m.title[:80]}")
        return "\n".join(lines)

    def _pipeline_status(self) -> str:
        return self._running_status()

    def _help(self) -> str:
        return (
            "**CTI Assistant — what I can tell you:**\n\n"
            "**Lookup by ID:**\n"
            "  `status of 4d24372645ad681b` — full pipeline trace\n"
            "  `show me abc123ef` — same\n\n"
            "**Queue & Processing:**\n"
            "  `what's in the queue?` — pending events\n"
            "  `what's running?` — current pipeline step\n"
            "  `what's complete?` — threats with validated mitigations\n\n"
            "**Results:**\n"
            "  `show patterns` — discovered attack patterns\n"
            "  `show mitigations` — generated recommendations\n"
            "  `my last submission` — most recently submitted threat\n\n"
            "**Or just ask in plain English!**"
        )

    # ── LLM fallback ────────────────────────────────────────────────────

    async def _llm_respond(self, message: str, history: List[Dict]) -> str:
        events = self.state.get('events', [])
        enriched = self.state.get('enriched_events', [])
        patterns = self.state.get('patterns', [])
        mitigations = self.state.get('mitigations', [])
        pending = self.state.get('pending_events', [])

        context = (
            f"Pipeline: {len(events)} events, {len(enriched)} enriched, "
            f"{len(patterns)} patterns, {len(mitigations)} mitigations, "
            f"{len(pending)} pending.\n"
            f"Status: {self.state.get('pipeline_status', 'idle')}.\n"
        )
        if enriched:
            last = enriched[-1]
            context += (
                f"Last enriched: id={last.event_id}, "
                f"category={last.threat_category}, "
                f"stage={last.attack_stage}, "
                f"confidence={last.enrichment_confidence:.2f}.\n"
            )

        system = (
            "You are a concise CTI analyst assistant embedded in a "
            "real-time threat intelligence dashboard. Answer in 2-4 sentences "
            "using only facts from the state below. Be direct and specific."
        )
        prompt = f"State:\n{context}\n\nUser: {message}"

        try:
            response = await self.llm.agenerate(prompt, system_prompt=system,
                                                 temperature=0.3)
            return (response or "").strip() or (
                "I couldn't generate a response. "
                "Try asking about a specific event ID or pipeline status."
            )
        except Exception:
            return (
                "LLM is busy right now. "
                "Try asking about a specific ID, queue, or pipeline status."
            )
