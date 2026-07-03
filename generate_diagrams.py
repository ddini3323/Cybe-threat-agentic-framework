"""
Run this script to generate all college report diagrams as PNG files.
Output folder: diagrams/
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patheffects as pe

os.makedirs("diagrams", exist_ok=True)


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def box(ax, x, y, w, h, text, fc="#d4edda", ec="#333", fs=9, bold=False,
        radius=0.04):
    fw = "bold" if bold else "normal"
    rect = FancyBboxPatch((x - w/2, y - h/2), w, h,
                          boxstyle=f"round,pad={radius}",
                          fc=fc, ec=ec, lw=1.2, zorder=3)
    ax.add_patch(rect)
    ax.text(x, y, text, ha="center", va="center", fontsize=fs,
            fontweight=fw, zorder=4)

def ellipse(ax, x, y, w, h, text, fc="#cce5ff", ec="#333", fs=9):
    e = mpatches.Ellipse((x, y), w, h, fc=fc, ec=ec, lw=1.2, zorder=3)
    ax.add_patch(e)
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, zorder=4)

def diamond(ax, x, y, w, h, text, fc="#fff3cd", ec="#333", fs=8):
    dx, dy = w/2, h/2
    pts = [(x, y+dy), (x+dx, y), (x, y-dy), (x-dx, y)]
    poly = plt.Polygon(pts, closed=True, fc=fc, ec=ec, lw=1.2, zorder=3)
    ax.add_patch(poly)
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, zorder=4)

def arrow(ax, x1, y1, x2, y2, label="", lfs=7, color="#333", dashed=False):
    ls = "--" if dashed else "-"
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="->", color=color,
                                lw=1.2, linestyle=ls), zorder=2)
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx, my, label, ha="center", va="bottom", fontsize=lfs,
                color="#555", zorder=5,
                bbox=dict(fc="white", ec="none", pad=1))

def save(fig, name):
    path = f"diagrams/{name}.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {path}")


# ──────────────────────────────────────────────────────────────────────────────
# 1. USE CASE DIAGRAM  (Chapter 3)
# ──────────────────────────────────────────────────────────────────────────────
def use_case():
    fig, ax = plt.subplots(figsize=(12, 9))
    ax.set_xlim(0, 12); ax.set_ylim(0, 9)
    ax.axis("off")
    ax.set_title("Use Case Diagram   [Chapter 3 – System Analysis]",
                 fontsize=12, fontweight="bold", pad=10)

    # system boundary
    sys_rect = FancyBboxPatch((2.5, 0.5), 7, 8,
                              boxstyle="round,pad=0.1",
                              fc="#f8f9fa", ec="#555", lw=1.5, zorder=1)
    ax.add_patch(sys_rect)
    ax.text(6, 8.65, "CTI Agentic System", ha="center", fontsize=10,
            fontweight="bold")

    # use cases
    ucs = [
        (6, 7.5, "Submit Threat (Text / File)"),
        (6, 6.3, "View Enriched Events"),
        (6, 5.1, "View Attack Patterns"),
        (6, 3.9, "Approve / Review Mitigation"),
        (6, 2.7, "Run Benchmark"),
        (6, 1.5, "Configure Feeds"),
    ]
    for x, y, t in ucs:
        ellipse(ax, x, y, 3.6, 0.7, t, fc="#cce5ff", fs=8)

    # actors
    for ay, lbl in [(5.1, "Security\nAnalyst"), (2.1, "System\nAdmin")]:
        ax.plot(0.9, ay+0.5, "o", ms=14, mfc="#adb5bd", mec="#555", zorder=5)
        ax.plot([0.9, 0.9], [ay+0.5-0.14, ay+0.5-0.5], lw=1.5, color="#555")
        ax.plot([0.6, 0.9], [ay+0.5-0.3, ay+0.5-0.2], lw=1.5, color="#555")
        ax.plot([0.9, 1.2], [ay+0.5-0.2, ay+0.5-0.3], lw=1.5, color="#555")
        ax.plot([0.7, 0.9], [ay+0.5-0.8, ay+0.5-0.5], lw=1.5, color="#555")
        ax.plot([0.9, 1.1], [ay+0.5-0.5, ay+0.5-0.8], lw=1.5, color="#555")
        ax.text(0.9, ay-0.35, lbl, ha="center", fontsize=8)

    # feed actor (right)
    ax.plot(11.1, 3.4, "o", ms=14, mfc="#adb5bd", mec="#555", zorder=5)
    ax.plot([11.1]*2, [3.26, 2.9], lw=1.5, color="#555")
    ax.plot([10.8, 11.1], [3.1, 3.2], lw=1.5, color="#555")
    ax.plot([11.1, 11.4], [3.2, 3.1], lw=1.5, color="#555")
    ax.plot([10.9, 11.1], [2.6, 2.9], lw=1.5, color="#555")
    ax.plot([11.1, 11.3], [2.9, 2.6], lw=1.5, color="#555")
    ax.text(11.1, 2.4, "Live Feed\n(Mastodon)", ha="center", fontsize=8)

    # arrows analyst → use cases
    for uy in [7.5, 6.3, 5.1, 3.9, 2.7]:
        arrow(ax, 1.3, 5.6, 4.2, uy)
    # admin
    for uy in [2.7, 1.5]:
        arrow(ax, 1.3, 2.6, 4.2, uy)
    # feed
    arrow(ax, 10.8, 3.4, 7.8, 7.5)

    save(fig, "01_use_case_diagram")

# ──────────────────────────────────────────────────────────────────────────────
# 2. DFD LEVEL 0  (Chapter 3)
# ──────────────────────────────────────────────────────────────────────────────
def dfd_level0():
    fig, ax = plt.subplots(figsize=(10, 7))
    ax.set_xlim(0, 10); ax.set_ylim(0, 7)
    ax.axis("off")
    ax.set_title("DFD Level 0 – Context Diagram   [Chapter 3 – System Analysis]",
                 fontsize=11, fontweight="bold", pad=10)

    # central system circle
    circ = plt.Circle((5, 3.5), 1.4, fc="#d4edda", ec="#333", lw=1.5, zorder=3)
    ax.add_patch(circ)
    ax.text(5, 3.5, "CTI\nAgentic\nSystem", ha="center", va="center",
            fontsize=9, fontweight="bold", zorder=4)

    # external entities
    for (x, y, t, fc) in [
        (1.2, 5.8, "Security\nAnalyst",          "#cce5ff"),
        (1.2, 1.2, "Live Feed\n(Mastodon/URLhaus)","#cce5ff"),
        (8.8, 5.8, "MITRE ATT&CK\nKnowledge Base","#fff3cd"),
        (8.8, 1.2, "SOC Dashboard\n(Analyst Output)","#f8d7da"),
    ]:
        box(ax, x, y, 2.0, 1.0, t, fc=fc, fs=8)

    # arrows
    arrow(ax, 2.2, 5.8, 3.8, 4.5, "Threat Text / File")
    arrow(ax, 2.2, 1.2, 3.8, 2.5, "Live CTI Feed Events")
    arrow(ax, 6.2, 4.5, 7.8, 5.8, "TTP / RAG Queries")
    arrow(ax, 7.8, 5.5, 6.2, 4.2, "Technique Context")
    arrow(ax, 6.2, 2.5, 7.8, 1.5, "Mitigations / Reports")
    arrow(ax, 7.8, 1.2, 6.2, 3.0, "Approval Decision")

    save(fig, "02_dfd_level0_context")

# ──────────────────────────────────────────────────────────────────────────────
# 3. DFD LEVEL 1  (Chapter 4)
# ──────────────────────────────────────────────────────────────────────────────
def dfd_level1():
    fig, ax = plt.subplots(figsize=(10, 13))
    ax.set_xlim(0, 10); ax.set_ylim(0, 13)
    ax.axis("off")
    ax.set_title("DFD Level 1 – Internal Pipeline Flows   [Chapter 4 – System Design]",
                 fontsize=11, fontweight="bold", pad=10)

    # external
    box(ax, 5, 12.3, 3.5, 0.7, "Analyst / Feed Input", fc="#cce5ff", fs=9)

    # processes
    procs = [
        (5, 11.0, "P1: Ingestion & Normalisation"),
        (5,  9.3, "P2: LLM Enrichment (RAG)"),
        (5,  7.5, "P3: Pattern Discovery"),
        (5,  5.7, "P4: Mitigation Generation"),
        (5,  3.9, "P5: Validation"),
    ]
    for x, y, t in procs:
        box(ax, x, y, 4.2, 0.7, t, fc="#d4edda", fs=9)

    # data stores
    box(ax, 8.5, 9.3, 2.2, 0.7, "D1: ChromaDB\n(MITRE+History)", fc="#fff3cd", fs=8)
    box(ax, 8.5, 7.5, 2.2, 0.7, "D2: Pattern\nStore",            fc="#fff3cd", fs=8)

    # output
    box(ax, 5, 2.5, 3.5, 0.7, "SOC Dashboard", fc="#f8d7da", fs=9)

    # vertical arrows
    arrow(ax, 5, 11.95, 5, 11.35, "raw threat data")
    arrow(ax, 5, 10.65, 5,  9.65, "ThreatEvent")
    arrow(ax, 5,  8.95, 5,  7.85, "EnrichedEvent")
    arrow(ax, 5,  7.15, 5,  6.05, "ThreatPattern")
    arrow(ax, 5,  5.35, 5,  4.25, "MitigationAction")
    arrow(ax, 5,  3.55, 5,  2.85, "validated result")

    # chroma arrows
    arrow(ax, 7.1, 9.3, 7.4, 9.3, "query",    dashed=True)
    arrow(ax, 7.4, 9.1, 7.1, 9.1, "context",  dashed=True)
    ax.annotate("store-back", xy=(7.35, 9.5), fontsize=7, color="#555")

    # pattern store arrows
    arrow(ax, 7.1, 7.5, 7.4, 7.5, "read/write", dashed=True)

    save(fig, "03_dfd_level1")

# ──────────────────────────────────────────────────────────────────────────────
# 4. ER / DATA MODEL  (Chapter 4)
# ──────────────────────────────────────────────────────────────────────────────
def er_diagram():
    fig, ax = plt.subplots(figsize=(13, 8))
    ax.set_xlim(0, 13); ax.set_ylim(0, 8)
    ax.axis("off")
    ax.set_title("ER / Data Model Diagram   [Chapter 4 – System Design]",
                 fontsize=11, fontweight="bold", pad=10)

    entities = [
        (2.5, 6.0, "ThreatEvent",
         ["PK  event_id : string (MD5)",
          "source : string",
          "event_type : enum",
          "severity : int (1-5)",
          "raw_text : string",
          "indicator : string",
          "timestamp : datetime"]),
        (9.5, 6.0, "EnrichedEvent",
         ["FK  event_id",
          "ttps[ ] : list",
          "iocs[ ] : list",
          "cves[ ] : list",
          "malware_family : string",
          "attack_vector : string",
          "enrichment_confidence : float"]),
        (2.5, 2.0, "ThreatPattern",
         ["PK  pattern_id : string",
          "pattern_name : string",
          "event_ids[ ] : list",
          "primary_ttp : string",
          "severity : int",
          "pattern_confidence : float"]),
        (9.5, 2.0, "MitigationAction",
         ["PK  mitigation_id : string",
          "FK  pattern_id",
          "title : string",
          "d3fend_codes[ ] : list",
          "priority : int (1-5)",
          "action_steps[ ] : list",
          "validated : bool"]),
    ]

    for (cx, cy, title, fields) in entities:
        row_h = 0.38
        total_h = (len(fields) + 1) * row_h
        top = cy + total_h / 2

        # header
        rect = FancyBboxPatch((cx-2.2, top-row_h), 4.4, row_h,
                              boxstyle="round,pad=0.02",
                              fc="#4472c4", ec="#333", lw=1, zorder=3)
        ax.add_patch(rect)
        ax.text(cx, top - row_h/2, title, ha="center", va="center",
                fontsize=9, fontweight="bold", color="white", zorder=4)

        for i, f in enumerate(fields):
            y0 = top - (i+2)*row_h
            fc = "#dce6f1" if i % 2 == 0 else "#eaf0fb"
            r = FancyBboxPatch((cx-2.2, y0), 4.4, row_h,
                               boxstyle="round,pad=0.01",
                               fc=fc, ec="#aaa", lw=0.5, zorder=3)
            ax.add_patch(r)
            ax.text(cx-2.1, y0 + row_h/2, f, va="center", fontsize=7.5,
                    zorder=4)

    # relationship arrows
    arrow(ax, 4.7, 6.0, 7.3, 6.0, "enriches →")
    arrow(ax, 2.5, 4.3, 2.5, 3.0, "clusters into ↓")
    arrow(ax, 4.7, 2.0, 7.3, 2.0, "triggers →")

    save(fig, "04_er_data_model")

# ──────────────────────────────────────────────────────────────────────────────
# 5. SEQUENCE DIAGRAM  (Chapter 4)
# ──────────────────────────────────────────────────────────────────────────────
def sequence_diagram():
    fig, ax = plt.subplots(figsize=(14, 10))
    ax.set_xlim(0, 14); ax.set_ylim(0, 10)
    ax.axis("off")
    ax.set_title("Sequence Diagram – Threat Processing Flow   [Chapter 4 – System Design]",
                 fontsize=11, fontweight="bold", pad=10)

    actors = ["Analyst", "FastAPI", "Ingest", "Enrich", "ChromaDB",
              "Pattern", "Mitigate", "Validate"]
    xs = [0.8, 2.4, 4.0, 5.6, 7.2, 8.8, 10.4, 12.0]

    # headers + lifelines
    for x, name in zip(xs, actors):
        box(ax, x, 9.5, 1.3, 0.5, name, fc="#4472c4", fs=8, bold=True)
        ax.plot([x]*2, [9.25, 0.3], lw=1, color="#999", ls="--", zorder=1)

    # messages (y, x_from, x_to, label, dashed)
    msgs = [
        (8.8, 0.8, 2.4, "POST /api/ingest/instant",  False),
        (8.2, 2.4, 4.0, "raw_text",                   False),
        (7.6, 4.0, 2.4, "ThreatEvent",                True),
        (7.0, 2.4, 5.6, "ThreatEvent",                False),
        (6.4, 5.6, 7.2, "embed + query",              False),
        (5.8, 7.2, 5.6, "MITRE context",              True),
        (5.2, 5.6, 5.6, "LLM prompt (llama3.2:3b)",  False),
        (4.6, 5.6, 5.6, "LLM JSON output",            True),
        (4.0, 5.6, 7.2, "store-back",                 False),
        (3.4, 5.6, 2.4, "EnrichedEvent",              True),
        (2.8, 2.4, 8.8, "EnrichedEvent",              False),
        (2.2, 8.8, 2.4, "ThreatPattern",              True),
        (1.6, 2.4, 10.4,"ThreatPattern",              False),
        (1.0, 10.4,2.4, "MitigationAction",           True),
        (0.5, 2.4, 12.0,"MitigationAction",           False),
    ]

    for y, x1, x2, lbl, ret in msgs:
        col = "#888" if ret else "#222"
        ls  = "--" if ret else "-"
        if x1 == x2:   # self-message
            ax.annotate("", xy=(x1+0.7, y), xytext=(x1, y),
                       arrowprops=dict(arrowstyle="->", color=col, lw=1))
            ax.plot([x1, x1+0.7, x1+0.7], [y, y, y-0.35], color=col, lw=1, ls=ls)
            ax.text(x1+0.75, y-0.17, lbl, fontsize=6.5, va="center", color="#444")
        else:
            ax.annotate("", xy=(x2, y), xytext=(x1, y),
                       arrowprops=dict(arrowstyle="->", color=col,
                                       lw=1.1, linestyle=ls))
            mx = (x1+x2)/2
            ax.text(mx, y+0.08, lbl, ha="center", fontsize=6.5, color="#444",
                    bbox=dict(fc="white", ec="none", pad=0.5))

    save(fig, "05_sequence_diagram")

# ──────────────────────────────────────────────────────────────────────────────
# 6. ACTIVITY / FLOWCHART  (Chapter 4)
# ──────────────────────────────────────────────────────────────────────────────
def activity_diagram():
    fig, ax = plt.subplots(figsize=(10, 18))
    ax.set_xlim(0, 10); ax.set_ylim(0, 18)
    ax.axis("off")
    ax.set_title("Activity Diagram / Flowchart   [Chapter 4 – System Design]",
                 fontsize=11, fontweight="bold", pad=10)

    W, H = 4.5, 0.6

    def proc(x, y, t, fc="#d4edda"):
        box(ax, x, y, W, H, t, fc=fc, fs=8.5)

    def dec(x, y, t):
        diamond(ax, x, y, 3.4, 0.7, t, fs=8)

    def term(x, y, t):
        e = mpatches.Ellipse((x, y), 2.5, 0.6, fc="#adb5bd", ec="#333", lw=1.5, zorder=3)
        ax.add_patch(e)
        ax.text(x, y, t, ha="center", va="center", fontsize=9,
                fontweight="bold", zorder=4)

    term(5, 17.4, "START")
    proc(5, 16.4, "Receive Threat Input\n(Text / JSON / CSV / Feed)")
    proc(5, 15.2, "Agent 1: Ingestion\nNormalise & Deduplicate")
    dec( 5, 13.9, "Duplicate?")
    proc(5, 12.6, "Agent 2: Enrichment\nLLM + RAG (ChromaDB)")
    dec( 5, 11.3, "Confidence > 0.3?")
    proc(5, 10.1, "Store enriched event\nto ChromaDB")
    proc(5,  8.9, "Agent 3: Pattern Discovery\nWeighted Jaccard Similarity")
    dec( 5,  7.6, "Severity ≥ 3?")
    proc(5,  6.4, "Agent 4: Mitigation\nCoT + D3FEND Mapping")
    proc(5,  5.2, "Agent 5: Validation\nSafety Rules Check")
    dec( 5,  3.9, "Passes\nValidation?")
    proc(5,  2.7, "Publish to SOC Dashboard", fc="#cce5ff")
    term(5,  1.7, "END")

    # side nodes
    box(ax, 8.5, 13.9, 2.2, 0.55, "Discard\n(duplicate skip)", fc="#f8d7da", fs=8)
    box(ax, 8.5,  7.6, 2.2, 0.55, "Log Only\n(no mitigation)",  fc="#fff3cd", fs=8)
    box(ax, 8.5,  3.9, 2.2, 0.55, "Flag & Log\n(rejected)",     fc="#f8d7da", fs=8)

    # main flow arrows
    for y1, y2, lbl in [
        (17.1, 16.7, ""),
        (16.1, 15.5, ""),
        (14.9, 14.25,""),
        (13.55,12.9, "No"),
        (12.3, 11.65,""),
        (10.95,10.4, "Yes"),
        (9.8,  9.2,  ""),
        (8.6,  7.95, ""),
        (7.25, 6.7,  "Yes"),
        (6.1,  5.5,  ""),
        (4.9,  4.25, ""),
        (3.55, 3.05, "Yes"),
        (2.4,  2.0,  ""),
    ]:
        arrow(ax, 5, y1, 5, y2, lbl)

    # side arrows
    arrow(ax, 6.7, 13.9, 7.4, 13.9, "Yes")
    arrow(ax, 6.7,  7.6, 7.4,  7.6, "No")
    arrow(ax, 6.7,  3.9, 7.4,  3.9, "No")

    # "No" label on confidence
    ax.text(5.15, 10.65, "No", fontsize=8, color="#555")

    save(fig, "06_activity_flowchart")


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Generating diagrams...")
    use_case()
    dfd_level0()
    dfd_level1()
    er_diagram()
    sequence_diagram()
    activity_diagram()
    print("\nAll diagrams saved to diagrams/ folder.")
    print("Files:")
    for f in sorted(os.listdir("diagrams")):
        print(f"  diagrams/{f}")
