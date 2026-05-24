"""
MITRE ATT&CK Loader
Downloads the MITRE ATT&CK Enterprise dataset (free, no API key)
and loads it into the vector store.

Uses the official MITRE ATT&CK STIX JSON (hosted on GitHub).
"""
import json
import hashlib
from typing import List, Dict
from pathlib import Path

import httpx

from .vector_store import CTIVectorStore
import config

# Official MITRE ATT&CK Enterprise STIX bundle (free, ~7MB)
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
MITRE_CACHE_FILE = config.BASE_DIR / "data" / "mitre_attack.json"


class MitreAttackLoader:
    """Downloads and indexes the MITRE ATT&CK framework into ChromaDB"""

    def __init__(self, store: CTIVectorStore):
        self.store = store

    def _download_stix(self) -> Dict:
        """Download MITRE ATT&CK STIX bundle (cached locally)"""
        if MITRE_CACHE_FILE.exists():
            print("  → Using cached MITRE ATT&CK data")
            with open(MITRE_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)

        print("  → Downloading MITRE ATT&CK Enterprise dataset (~7MB)...")
        with httpx.Client(timeout=120, follow_redirects=True) as client:
            resp = client.get(MITRE_STIX_URL)
            resp.raise_for_status()
            data = resp.json()

        MITRE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(MITRE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
        print(f"  → Saved to {MITRE_CACHE_FILE}")
        return data

    def _parse_techniques(self, stix_bundle: Dict) -> List[Dict]:
        """Extract techniques from STIX bundle"""
        techniques = []
        tactic_map = {}

        # Build tactic name map from x-mitre-tactic objects
        for obj in stix_bundle.get("objects", []):
            if obj.get("type") == "x-mitre-tactic":
                short = obj.get("x_mitre_shortname", "")
                name = obj.get("name", "")
                tactic_map[short] = name

        for obj in stix_bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            # Get technique ID (e.g. T1059)
            ext_refs = obj.get("external_references", [])
            tid = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if not tid:
                continue

            # Get tactic names
            kill_chain = obj.get("kill_chain_phases", [])
            tactics = [
                tactic_map.get(kc["phase_name"], kc["phase_name"])
                for kc in kill_chain
                if kc.get("kill_chain_name") == "mitre-attack"
            ]

            desc = obj.get("description", "")
            # Trim very long descriptions to keep embeddings focused
            if len(desc) > 800:
                desc = desc[:800] + "..."

            techniques.append({
                "id": tid,
                "name": obj.get("name", ""),
                "description": desc,
                "tactic": ", ".join(tactics),
            })

        return techniques

    def load(self, force_reload: bool = False) -> int:
        """
        Load MITRE ATT&CK into vector store.
        Skips if already loaded unless force_reload=True.
        Returns the number of techniques indexed.
        """
        if self.store.mitre_loaded() and not force_reload:
            count = self.store.mitre.count()
            print(f"  → MITRE ATT&CK already indexed ({count} techniques)")
            return count

        print("Loading MITRE ATT&CK framework...")
        stix = self._download_stix()
        techniques = self._parse_techniques(stix)
        print(f"  → Parsed {len(techniques)} techniques")

        self.store.add_mitre_techniques(techniques)
        print(f"  → Indexed {len(techniques)} techniques into ChromaDB")
        return len(techniques)
