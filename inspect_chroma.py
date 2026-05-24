from rag.vector_store import CTIVectorStore

vs = CTIVectorStore()

print("=== ChromaDB Collections ===")
print("MITRE techniques indexed:", vs.mitre.count())
print("Threat reports stored:   ", vs.reports.count())
print()

results = vs.mitre.get(limit=8, include=["documents", "metadatas"])
print("=== Sample MITRE ATT&CK Techniques (first 8) ===")
for i in range(len(results["documents"])):
    m = results["metadatas"][i]
    d = results["documents"][i]
    print(str(i+1) + ". [" + m["technique_id"] + "] " + m["name"] + " | Tactic: " + m["tactic"])
    print("   " + d[:150])
    print()

print("=== Semantic Search Test ===")
print("Query: 'PowerShell malware execution'")
hits = vs.query_mitre("PowerShell malware execution", n_results=5)
for h in hits:
    print("  -> [" + h["technique_id"] + "] " + h["name"] + " | sim=" + str(round(h["similarity"],3)) + " | " + h["snippet"][:100])

print()
print("Query: 'phishing email credential theft'")
hits2 = vs.query_mitre("phishing email credential theft", n_results=5)
for h in hits2:
    print("  -> [" + h["technique_id"] + "] " + h["name"] + " | sim=" + str(round(h["similarity"],3)) + " | " + h["snippet"][:100])

print()
if vs.reports.count() > 0:
    print("=== Stored Threat Reports (first 3) ===")
    rpts = vs.reports.get(limit=3, include=["documents", "metadatas"])
    for i in range(len(rpts["documents"])):
        m = rpts["metadatas"][i]
        d = rpts["documents"][i]
        print(str(i+1) + ". Source: " + str(m.get("source","?")) + " | TTPs: " + str(m.get("ttps","?")))
        print("   " + d[:180])
        print()
else:
    print("=== Threat Reports collection: empty (pipeline not yet run) ===")
