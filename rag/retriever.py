"""
CTI Retriever
High-level interface used by the EnrichmentAgent to fetch
relevant MITRE ATT&CK context before each LLM call.
"""
from typing import List, Dict, Optional

from .vector_store import CTIVectorStore

# Only include results above this similarity threshold
SIMILARITY_THRESHOLD = 0.35


class CTIRetriever:
    """Retrieves relevant CTI context from the vector store"""

    def __init__(self, store: CTIVectorStore):
        self.store = store

    def get_mitre_context(self, threat_text: str, n: int = 5) -> str:
        """
        Retrieves the top-N most relevant MITRE ATT&CK techniques
        and formats them as a context block for the LLM prompt.
        Returns an empty string if the store has no data.
        """
        results = self.store.query_mitre(threat_text, n_results=n)
        # Filter by similarity threshold
        results = [r for r in results if r["similarity"] >= SIMILARITY_THRESHOLD]
        if not results:
            return ""

        lines = ["Relevant MITRE ATT&CK techniques (use these for TTP mapping):"]
        for r in results:
            lines.append(
                f"  - {r['technique_id']} ({r['name']}) "
                f"[Tactic: {r['tactic']}] — similarity: {r['similarity']}"
            )
            lines.append(f"    {r['snippet'][:180]}")
        return "\n".join(lines)

    def get_similar_threats_context(self, threat_text: str, n: int = 3) -> str:
        """
        Retrieves similar past enriched threats for additional context.
        Returns an empty string if no historical data exists.
        """
        results = self.store.query_similar_threats(threat_text, n_results=n)
        results = [r for r in results if r["similarity"] >= SIMILARITY_THRESHOLD]
        if not results:
            return ""

        lines = ["Similar historical threats seen before:"]
        for r in results:
            lines.append(
                f"  - [{r['source']}] similarity: {r['similarity']} — {r['snippet'][:180]}"
            )
        return "\n".join(lines)

    def store_enriched_event(self, event_id: str, threat_text: str,
                              source: str, ttps: List[str], malware: Optional[str]):
        """
        Stores an enriched event into the threat_reports collection
        so future events can learn from it.
        """
        self.store.add_threat_report(
            event_id=event_id,
            text=threat_text,
            metadata={
                "event_id": event_id,
                "source": source,
                "ttps": ", ".join(ttps) if ttps else "",
                "malware": malware or "",
            },
        )

    def is_ready(self) -> bool:
        """True if MITRE ATT&CK data is indexed"""
        return self.store.mitre_loaded()
