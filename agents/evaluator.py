"""
Agent: Evaluator / Benchmarking  (Objective 4)
Evaluates system performance across all pipeline stages:
  - TTP extraction rate and enrichment confidence
  - Classification confidence
  - Mitigation relevance (LLM self-evaluation)
  - High-severity event coverage

Research basis: Gap identified in P7 (CTIArena, Cheng et al. 2025) and
P3 (Salek et al., IEEE Access 2025) — no systematic evaluation framework
for context-aware CTI pipelines.
"""
import hashlib
from typing import List, Optional
from datetime import datetime

from models import (EnrichedEvent, ThreatClassification, MitigationAction,
                    BenchmarkResult, AgentLogEntry, SeverityLevel)
from llm_wrapper import LLMWrapper
import config


class EvaluatorAgent:
    """Evaluates pipeline performance and benchmarks output quality (Objective 4)"""

    def __init__(self, llm: LLMWrapper):
        self.name = "EvaluatorAgent"
        self.llm = llm
        self.log_entries: List[AgentLogEntry] = []
        self.results: List[BenchmarkResult] = []

    def _log(self, action: str, details: str, status: str = "success"):
        entry = AgentLogEntry(
            agent_name=self.name,
            action=action,
            details=details,
            status=status
        )
        self.log_entries.append(entry)
        return entry

    # ------------------------------------------------------------------ #
    # Metric 1: TTP extraction rate
    # ------------------------------------------------------------------ #
    def _compute_ttp_extraction_rate(self, events: List[EnrichedEvent]) -> float:
        """% of enriched events that have at least one TTP extracted"""
        if not events:
            return 0.0
        with_ttps = sum(1 for e in events if e.ttps)
        return round(with_ttps / len(events), 4)

    # ------------------------------------------------------------------ #
    # Metric 2: Average enrichment confidence
    # ------------------------------------------------------------------ #
    def _compute_avg_enrichment_confidence(self, events: List[EnrichedEvent]) -> float:
        if not events:
            return 0.0
        return round(sum(e.enrichment_confidence for e in events) / len(events), 4)

    # ------------------------------------------------------------------ #
    # Metric 3: Average classification confidence
    # ------------------------------------------------------------------ #
    def _compute_avg_classification_confidence(
        self, classifications: List[ThreatClassification]
    ) -> float:
        if not classifications:
            return 0.0
        return round(
            sum(c.classification_confidence for c in classifications) / len(classifications),
            4
        )

    # ------------------------------------------------------------------ #
    # Metric 4: High-severity coverage
    # ------------------------------------------------------------------ #
    def _compute_high_severity_coverage(
        self,
        events: List[EnrichedEvent],
        mitigations: List[MitigationAction]
    ) -> float:
        """% of HIGH+ severity events that have an associated mitigation"""
        high_events = [
            e for e in events
            if e.original_event.severity >= config.MIN_SEVERITY_FOR_MITIGATION
        ]
        if not high_events:
            return 1.0  # No high-severity events → trivially covered
        mitigated_ids = {m.event_id for m in mitigations if m.event_id}
        covered = sum(1 for e in high_events if e.event_id in mitigated_ids)
        return round(covered / len(high_events), 4)

    # ------------------------------------------------------------------ #
    # Metric 5: Mitigation relevance (LLM self-evaluation)
    # ------------------------------------------------------------------ #
    async def _evaluate_mitigation_relevance(
        self, mitigation: MitigationAction, event: Optional[EnrichedEvent]
    ) -> float:
        """Ask LLM to score how relevant a mitigation is to its source event (0-1)"""
        if not event:
            return 0.5  # Default when we can't evaluate

        context = (
            f"Threat: {event.original_event.raw_text[:300]}\n"
            f"Attack stage: {event.attack_stage or 'Unknown'}\n"
            f"TTPs: {', '.join(event.ttps[:3]) if event.ttps else 'None'}"
        )
        mitigation_summary = (
            f"Title: {mitigation.title}\n"
            f"Steps: {'; '.join(mitigation.steps[:3])}"
        )
        prompt = f"""Rate how relevant this mitigation is to the given threat (0.0 to 1.0).

Threat:
{context}

Proposed Mitigation:
{mitigation_summary}

Reply with ONLY a JSON object: {{"relevance_score": <float 0.0-1.0>, "reason": "<one sentence>"}}"""

        try:
            result = await self.llm.agenerate_json(prompt, "You are a cybersecurity evaluator.")
            if result and "relevance_score" in result:
                return float(result["relevance_score"])
        except Exception:
            pass
        return 0.5

    # ------------------------------------------------------------------ #
    # Main benchmark runner
    # ------------------------------------------------------------------ #
    async def run_benchmark(
        self,
        enriched_events: List[EnrichedEvent],
        classifications: List[ThreatClassification],
        mitigations: List[MitigationAction],
    ) -> BenchmarkResult:
        """Run a full benchmark pass and return scored results"""
        self._log("run_benchmark",
                  f"Starting benchmark: {len(enriched_events)} events, "
                  f"{len(classifications)} classifications, "
                  f"{len(mitigations)} mitigations")

        # Build event lookup for mitigation relevance evaluation
        event_map = {e.event_id: e for e in enriched_events}

        # Metrics 1-3 (no LLM calls needed)
        ttp_rate = self._compute_ttp_extraction_rate(enriched_events)
        avg_enrich_conf = self._compute_avg_enrichment_confidence(enriched_events)
        avg_class_conf = self._compute_avg_classification_confidence(classifications)
        high_sev_cov = self._compute_high_severity_coverage(enriched_events, mitigations)

        # Metric 5: Mitigation relevance (LLM call — sample up to 5 mitigations)
        sample_mitigations = [m for m in mitigations if m.event_id][:5]
        relevance_scores = []
        for m in sample_mitigations:
            score = await self._evaluate_mitigation_relevance(m, event_map.get(m.event_id))
            relevance_scores.append(score)
        avg_relevance = (
            round(sum(relevance_scores) / len(relevance_scores), 4)
            if relevance_scores else 0.0
        )

        run_id = hashlib.md5(
            f"benchmark_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        result = BenchmarkResult(
            run_id=run_id,
            total_events_tested=len(enriched_events),
            ttp_extraction_rate=ttp_rate,
            avg_enrichment_confidence=avg_enrich_conf,
            avg_classification_confidence=avg_class_conf,
            avg_mitigation_relevance=avg_relevance,
            high_severity_coverage=high_sev_cov,
            notes=(
                f"TTP extraction: {ttp_rate*100:.1f}% events have TTPs | "
                f"Enrichment confidence: {avg_enrich_conf:.2f} | "
                f"Classification confidence: {avg_class_conf:.2f} | "
                f"Mitigation relevance: {avg_relevance:.2f} | "
                f"High-severity coverage: {high_sev_cov*100:.1f}%"
            ),
        )

        self.results.append(result)
        self._log("run_benchmark",
                  f"Benchmark complete — run_id={run_id} | "
                  f"TTP rate={ttp_rate:.2f}, avg_conf={avg_enrich_conf:.2f}, "
                  f"relevance={avg_relevance:.2f}, hs_cov={high_sev_cov:.2f}")
        return result

    def get_all_results(self) -> List[BenchmarkResult]:
        return self.results
