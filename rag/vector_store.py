"""
ChromaDB Vector Store wrapper.
Manages the persistent local vector database for CTI knowledge.
Collections:
  - mitre_techniques  : MITRE ATT&CK technique descriptions
  - threat_reports    : Past enriched threat events (self-learning)
"""
import os
from pathlib import Path
from typing import List, Dict, Optional

import chromadb
from chromadb.utils import embedding_functions

import config

# Path for persistent ChromaDB storage
CHROMA_DIR = config.BASE_DIR / "data" / "chroma_db"
CHROMA_DIR.mkdir(parents=True, exist_ok=True)

# Use the lightweight all-MiniLM-L6-v2 model (22MB, CPU-friendly)
_EMBED_MODEL = "all-MiniLM-L6-v2"


class CTIVectorStore:
    """Persistent ChromaDB-backed vector store for CTI knowledge"""

    def __init__(self):
        self.client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        self._ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=_EMBED_MODEL
        )
        self.mitre = self._get_or_create("mitre_techniques")
        self.reports = self._get_or_create("threat_reports")

    def _get_or_create(self, name: str):
        return self.client.get_or_create_collection(
            name=name,
            embedding_function=self._ef,
            metadata={"hnsw:space": "cosine"},
        )

    # ── MITRE collection ──────────────────────────────────────────────

    def add_mitre_techniques(self, techniques: List[Dict]):
        """
        Bulk-load MITRE ATT&CK techniques.
        Each dict must have: id, name, description, tactic(s)
        """
        if not techniques:
            return
        ids, docs, metas = [], [], []
        for t in techniques:
            tid = t.get("id", "")
            if not tid:
                continue
            text = f"{tid} - {t.get('name','')}: {t.get('description','')}"
            ids.append(tid)
            docs.append(text)
            metas.append({
                "technique_id": tid,
                "name": t.get("name", ""),
                "tactic": t.get("tactic", ""),
            })
        if ids:
            self.mitre.upsert(ids=ids, documents=docs, metadatas=metas)

    def query_mitre(self, text: str, n_results: int = 5) -> List[Dict]:
        """Find the most relevant MITRE ATT&CK techniques for a threat description"""
        if self.mitre.count() == 0:
            return []
        results = self.mitre.query(
            query_texts=[text],
            n_results=min(n_results, self.mitre.count()),
            include=["documents", "metadatas", "distances"],
        )
        out = []
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            out.append({
                "technique_id": meta.get("technique_id"),
                "name": meta.get("name"),
                "tactic": meta.get("tactic"),
                "similarity": round(1 - dist, 3),
                "snippet": doc[:200],
            })
        return out

    def mitre_loaded(self) -> bool:
        return self.mitre.count() > 0

    # ── Threat reports collection (self-learning) ─────────────────────

    def add_threat_report(self, event_id: str, text: str, metadata: Dict):
        """Store an enriched event for future retrieval"""
        self.reports.upsert(
            ids=[event_id],
            documents=[text],
            metadatas=[metadata],
        )

    def query_similar_threats(self, text: str, n_results: int = 3) -> List[Dict]:
        """Find historically similar threats"""
        if self.reports.count() == 0:
            return []
        results = self.reports.query(
            query_texts=[text],
            n_results=min(n_results, self.reports.count()),
            include=["documents", "metadatas", "distances"],
        )
        out = []
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            out.append({
                "event_id": meta.get("event_id"),
                "source": meta.get("source"),
                "similarity": round(1 - dist, 3),
                "snippet": doc[:200],
            })
        return out

    def reports_count(self) -> int:
        return self.reports.count()
