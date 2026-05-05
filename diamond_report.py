#!/usr/bin/env python3
"""
diamond_report.py
Reads all Diamond Model JSON files from a directory and produces:
  - A CLI summary table printed to stdout
  - An HTML report with:
      * A summary table
      * An activity-thread table (like Figure 6 of the Diamond Model paper),
        with events ordered by start time and connected by directed arcs
        based on explicit related_events links (direct causation only — no
        transitive closure).
      * A visual diamond diagram per event

Usage:
    python diamond_report.py <json_dir> [output.html]

Arguments:
    json_dir      Directory containing Diamond Model .json files.
                  Files are processed in filename order (i.e. chronologically,
                  given the YYYY-MM-DD--HH-MM_name.json naming convention).
    output.html   Optional output path.
                  Defaults to <json_dir>/diamond_report.html

Dependencies:
    - 'rich' for a fancy CLI table  (pip install rich)
      Falls back to plain-text table if not installed.
    - No external dependencies for the HTML report.

Activity-thread arc rendering:
    confidence = 1.0        → solid line      (confirmed)
    confidence = 0.5–0.99   → dashed line     (probable)
    confidence < 0.5        → dotted line     (hypothesised)
"""

import json
import sys
import html as html_lib
from pathlib import Path
from datetime import datetime

# Optional: rich for CLI output
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box as rich_box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_events(json_dir: Path) -> list[dict]:
    """Load and return all JSON event files, sorted by filename."""
    files = sorted(json_dir.glob("*.json"))
    events =[]
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            data["_filename"] = f.name
            data["_stem"]     = f.stem  # filename without .json — used for relation lookup
            events.append(data)
        except Exception as e:
            print(f"Warning: could not parse {f.name}: {e}", file=sys.stderr)
    return events


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def svg_wrap(text, width_chars=20):
    """Word-wrap text for SVG tspan elements."""
    words = text.split()
    lines, curr = [],[]
    for w in words:
        if len(" ".join(curr + [w])) <= width_chars:
            curr.append(w)
        else:
            lines.append(" ".join(curr))
            curr = [w]
    if curr:
        lines.append(" ".join(curr))
    return lines


def safe_get(obj, *keys, default="—"):
    """Safely traverse nested dicts; returns a display string."""
    for k in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(k)
        if obj is None:
            return default
    if isinstance(obj, list):
        return ", ".join(str(x) for x in obj) if obj else default
    return str(obj).strip() if str(obj).strip() else default


def h(text) -> str:
    """HTML-escape a value safely."""
    return html_lib.escape(str(text)) if text else ""


def truncate(s: str, n: int) -> str:
    return (s[:n] + "…") if len(s) > n else s


# ---------------------------------------------------------------------------
# CLI output
# ---------------------------------------------------------------------------

def build_cli_rows(events: list[dict]) -> list[dict]:
    rows =[]
    for e in events:
        inc  = e.get("incident", {})
        ts   = e.get("meta_features", {}).get("timestamp", {})
        dm   = e.get("diamond_model", {})
        mf   = e.get("meta_features", {})
        resp = e.get("response", {})

        ongoing = resp.get("ongoing")
        ongoing_str = "⚠ YES" if ongoing is True else ("no" if ongoing is False else "?")

        atk_types = mf.get("methodology", {}).get("attack_type",[])
        cap_str   = truncate(", ".join(atk_types), 35) if atk_types else "—"

        assets    = dm.get("victim", {}).get("assets",[])
        vic_str   = truncate(", ".join(a.get("asset", "") for a in assets if a.get("asset")), 28) or "—"

        inf       = dm.get("infrastructure", {})
        n_ip      = len(inf.get("ip_addresses",[]))
        n_dom     = len(inf.get("domains",[]))
        inf_str   = f"{n_ip} IP / {n_dom} dom" if (n_ip or n_dom) else "—"

        ioc_count = len(dm.get("capability", {}).get("iocs",[]))
        adv_name  = dm.get("adversary", {}).get("name") or "—"

        rows.append({
            "id":       safe_get(inc, "id"),
            "detect":   safe_get(ts, "detection"),
            "ongoing":  ongoing_str,
            "adversary":truncate(adv_name, 18),
            "capab":    cap_str,
            "infra":    inf_str,
            "victim":   vic_str,
            "iocs":     str(ioc_count),
        })
    return rows


def print_cli_table(events: list[dict]):
    rows = build_cli_rows(events)
    if not rows:
        print("No events to display.")
        return

    if HAS_RICH:
        _cli_rich(rows)
    else:
        _cli_plain(rows)


def _cli_rich(rows: list[dict]):
    console = Console()
    table   = Table(
        title       = "Diamond Model — Event Summary",
        box         = rich_box.SIMPLE_HEAVY,
        header_style= "bold cyan",
        show_lines  = False,
    )
    cols    =["ID", "Detection", "Ongoing", "Adversary", "Attack Type", "Infrastructure", "Victim Assets", "IoCs"]
    keys    =["id", "detect", "ongoing", "adversary", "capab", "infra", "victim", "iocs"]
    for c in cols:
        table.add_column(c)

    for r in rows:
        style = "bold red" if r["ongoing"].startswith("⚠") else None
        table.add_row(*[r[k] for k in keys], style=style)

    console.print()
    console.print(table)


def _cli_plain(rows: list[dict]):
    cols =["id", "detect", "ongoing", "adversary", "capab", "infra", "victim", "iocs"]
    hdrs =["ID", "Detection", "Ongoing", "Adversary", "Attack Type", "Infrastructure", "Victim Assets", "IoCs"]
    widths = [max(len(hdrs[i]), max(len(r[c]) for r in rows)) for i, c in enumerate(cols)]

    sep    = "  ".join("─" * w for w in widths)
    header = "  ".join(h.ljust(widths[i]) for i, h in enumerate(hdrs))

    print()
    print("  Diamond Model — Event Summary")
    print("  " + "═" * len(sep))
    print("  " + header)
    print("  " + sep)
    for r in rows:
        print("  " + "  ".join(r[c].ljust(widths[i]) for i, c in enumerate(cols)))
    print()


# ---------------------------------------------------------------------------
# HTML: confidence badges
# ---------------------------------------------------------------------------

CONF_COLORS = {
    "confirmed":   ("#00ff88", "rgba(0,255,136,0.08)"),
    "probable":    ("#ffcc00", "rgba(255,204,0,0.08)"),
    "possible":    ("#ff8800", "rgba(255,136,0,0.08)"),
    "hypothesized":("#ff8800", "rgba(255,136,0,0.08)"),
    "hypothesised":("#ff8800", "rgba(255,136,0,0.08)"),
    "unknown":     ("#445566", "rgba(68,85,102,0.1)"),
    "discredited": ("#ff4455", "rgba(255,68,85,0.08)"),
}
def parse_confidence_value(val) -> float:
    if val is None:
        return 1.0
    try:
        return float(val)
    except (ValueError, TypeError):
        v = str(val).strip().lower()
        if v in["high", "confirmed", "certain"]: return 1.0
        if v in["medium", "probable", "likely"]: return 0.8
        if v in["low", "possible", "hypothesized", "hypothesised", "suspected"]: return 0.4
        if v in["discredited", "false", "none"]: return 0.0
        return 1.0

def get_confidence_color(val) -> tuple[str, str]:
    if val is None:
        return CONF_COLORS["unknown"]
    try:
        f = float(val)
        if f >= 0.9: return CONF_COLORS["confirmed"]
        if f >= 0.5: return CONF_COLORS["probable"]
        if f >= 0.1: return CONF_COLORS["possible"]
        if f <= 0.0: return CONF_COLORS["discredited"]
        return CONF_COLORS["hypothesized"]
    except (ValueError, TypeError):
        pass
    
    v = str(val).strip().lower()
    if v in ["confirmed", "high", "certain"]:
        return CONF_COLORS["confirmed"]
    if v in ["probable", "medium", "likely"]:
        return CONF_COLORS["probable"]
    if v in ["possible", "low", "hypothesized", "hypothesised", "suspected"]:
        return CONF_COLORS["possible"]
    if v in ["discredited", "false", "none"]:
        return CONF_COLORS["discredited"]
    
    return CONF_COLORS["unknown"]


# Arc colors aligned with confidence palette:
ARC_COLORS = {
    "solid":  "#00ff88",   # confirmed  → green
    "dashed": "#ffcc00",   # probable   → amber
    "dotted": "#ff8800",   # hypothesised → orange
}

def badge(confidence: str) -> str:
    fg, bg = get_confidence_color(confidence)
    return (f'<span class="badge" style="color:{fg};background:{bg};'
            f'border-color:{fg}">{h(confidence)}</span>')


# ---------------------------------------------------------------------------
# HTML: diamond SVG per event
# ---------------------------------------------------------------------------

def diamond_svg(e: dict, idx: int, is_hover: bool = False) -> str:
    """
    Renders the graphical Diamond Model for hover boxes and detail cards.
    Designed for a coordinate space viewBox="-20 -20 540 540".
    """
    dm  = e.get("diamond_model", {})
    mf  = e.get("meta_features", {})

    adv_node = dm.get("adversary", {})
    adv = adv_node.get("name") or "Unknown"
    adv_conf = adv_node.get("confidence", "unknown")

    vic_node = dm.get("victim", {})
    assets = vic_node.get("assets", [])
    vic    = assets[0].get("asset", "Unknown") if assets else "Unknown"
    vic_conf = vic_node.get("confidence", "unknown")

    cap_node = dm.get("capability", {})
    atk_types = mf.get("methodology", {}).get("attack_type", [])
    cap = atk_types[0] if atk_types else (cap_node.get("description") or "Unknown")
    cap_conf = cap_node.get("confidence", "unknown")

    inf_node = dm.get("infrastructure", {})
    ips     = inf_node.get("ip_addresses",[])
    doms    = inf_node.get("domains", [])
    infra   = ips[0].get("value", "") if ips else doms[0].get("value", "") if doms else "Unknown"
    infra_conf = inf_node.get("confidence", "unknown")

    iocs_count = len(cap_node.get("iocs",[]))

    # Center and geometry
    CX, CY = 250, 250
    R = 140
    top_x, top_y = CX, CY - R
    bot_x, bot_y = CX, CY + R
    lft_x, lft_y = CX - R, CY
    rgt_x, rgt_y = CX + R, CY

    def node_color(c): return get_confidence_color(c)[0]

    C_ADV = node_color(adv_conf)
    C_VIC = node_color(vic_conf)
    C_CAP = node_color(cap_conf)
    C_INF = node_color(infra_conf)

    FONT = "Share Tech Mono, monospace"

    def wrap_text(val: str, width: int = 24) -> list[str]:
        if not val: return ["Unknown"]
        words = val.split()
        lines = []
        curr_line = ""
        for w in words:
            sub_words = []
            while len(w) > width:
                sub_words.append(w[:width])
                w = w[width:]
            if w:
                sub_words.append(w)
            
            for sw in sub_words:
                if not curr_line:
                    curr_line = sw
                elif len(curr_line) + 1 + len(sw) <= width:
                    curr_line += " " + sw
                else:
                    lines.append(curr_line)
                    curr_line = sw
        if curr_line:
            lines.append(curr_line)
        return lines

    adv_lines   = wrap_text(adv, 24)
    vic_lines   = wrap_text(vic, 24)
    infra_lines = wrap_text(infra, 24)
    cap_lines   = wrap_text(cap, 24)

    adv_text = ""
    start_y = top_y - 20
    for i, line in enumerate(reversed(adv_lines)):
        y = start_y - i * 16
        adv_text += f'\n<text x="{top_x}" y="{y}" text-anchor="middle" font-family="{FONT}" font-size="15" fill="#e2e8f0">{h(line)}</text>'
    label_y = start_y - len(adv_lines) * 16 - 4
    adv_text += f'\n<text x="{top_x}" y="{label_y}" text-anchor="middle" font-family="{FONT}" font-size="12" font-weight="bold" letter-spacing="2" fill="#4a5a78">ADVERSARY</text>'

    start_y = bot_y + 28
    vic_text = ""
    for i, line in enumerate(vic_lines):
        y = start_y + i * 16
        vic_text += f'\n<text x="{bot_x}" y="{y}" text-anchor="middle" font-family="{FONT}" font-size="15" fill="#e2e8f0">{h(line)}</text>'
    label_y = start_y + len(vic_lines) * 16 + 4
    vic_text += f'\n<text x="{bot_x}" y="{label_y}" text-anchor="middle" font-family="{FONT}" font-size="12" font-weight="bold" letter-spacing="2" fill="#4a5a78">VICTIM</text>'

    infra_y = rgt_y - 8
    infra_labels = f'<text x="{rgt_x + 20}" y="{infra_y}" text-anchor="start" font-family="{FONT}" font-size="12" font-weight="bold" letter-spacing="2" fill="#4a5a78">INFRA</text>'
    for li, line in enumerate(infra_lines):
        infra_labels += f'\n<text x="{rgt_x + 20}" y="{infra_y + 18 + li*16}" text-anchor="start" font-family="{FONT}" font-size="14" fill="#e2e8f0">{h(line)}</text>'

    cap_y = lft_y - 8
    cap_labels = f'<text x="{lft_x - 20}" y="{cap_y}" text-anchor="end" font-family="{FONT}" font-size="12" font-weight="bold" letter-spacing="2" fill="#4a5a78">CAPABILITY</text>'
    for li, line in enumerate(cap_lines):
        cap_labels += f'\n<text x="{lft_x - 20}" y="{cap_y + 18 + li*16}" text-anchor="end" font-family="{FONT}" font-size="14" fill="#e2e8f0">{h(line)}</text>'

    defs = ""
    poly_filter = ""
    node_filter = ""
    if is_hover:
        eid = f"h-{idx}"
        defs = f'''
        <defs>
          <filter id="glow-{eid}"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
          <filter id="nglow-{eid}"><feGaussianBlur stdDeviation="4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        </defs>
        '''
        poly_filter = f'filter="url(#glow-{eid})"'
        node_filter = f'filter="url(#nglow-{eid})"'

    return f'''
    {defs}
    <polygon points="{top_x},{top_y} {rgt_x},{rgt_y} {bot_x},{bot_y} {lft_x},{lft_y}"
             fill="rgba(0,212,255,0.03)" stroke="#2a3b52" stroke-width="1.5" {poly_filter}/>
    <path d="M{top_x},{top_y} L{bot_x},{bot_y} M{lft_x},{lft_y} L{rgt_x},{rgt_y}"
          stroke="#2a3b52" stroke-width="1" stroke-dasharray="4,4"/>

    <circle cx="{top_x}" cy="{top_y}" r="8" fill="{C_ADV}" {node_filter}/>
    <circle cx="{rgt_x}" cy="{rgt_y}" r="8" fill="{C_INF}" {node_filter}/>
    <circle cx="{bot_x}" cy="{bot_y}" r="8" fill="{C_VIC}" {node_filter}/>
    <circle cx="{lft_x}" cy="{lft_y}" r="8" fill="{C_CAP}" {node_filter}/>

    {adv_text}
    {vic_text}
    {cap_labels}
    {infra_labels}

    <text x="{CX}" y="{CY - 6}"  text-anchor="middle" font-family="{FONT}" font-size="11" letter-spacing="2" fill="#4a5a78">IoCs</text>
    <text x="{CX}" y="{CY + 18}" text-anchor="middle" font-family="{FONT}" font-size="28" font-weight="bold" fill="#00d4ff">{iocs_count}</text>
    '''

# ---------------------------------------------------------------------------
# Activity-thread table
# ---------------------------------------------------------------------------

KILL_CHAIN_PHASES =[
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "C2",
    "Action on Objectives",
]

PHASE_ROW = {p.lower(): i for i, p in enumerate(KILL_CHAIN_PHASES)}

PHASE_ALIASES = {
    "recon":        "Reconnaissance",
    "weapon":       "Weaponization",
    "weaponise":    "Weaponization",
    "weaponize":    "Weaponization",
    "deliver":      "Delivery",
    "exploit":      "Exploitation",
    "install":      "Installation",
    "command":      "C2",
    "c&c":          "C2",
    "cnc":          "C2",
    "action":       "Action on Objectives",
    "objective":    "Action on Objectives",
    "exfil":        "Action on Objectives",
}

def canonical_phase(raw: str | None) -> str | None:
    if not raw:
        return None
    lower = raw.strip().lower()
    for p in KILL_CHAIN_PHASES:
        if p.lower() == lower: return p
    for alias, canon in PHASE_ALIASES.items():
        if alias in lower: return canon
    return None

def parse_attack_start(ts_str: str | None) -> datetime | None:
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            pass
    return None

def _arc_style(confidence: float) -> str:
    if confidence >= 1.0: return "none"
    elif confidence >= 0.5: return "8,5"
    else: return "3,4"

def _arc_color(confidence: float) -> str:
    if confidence >= 1.0: return ARC_COLORS["solid"]
    elif confidence >= 0.5: return ARC_COLORS["dashed"]
    else: return ARC_COLORS["dotted"]

def build_activity_thread_svg(events: list[dict]) -> str:
    """Non-interactive activity-thread table generation (retained for backward compatibility)."""
    # ── 1. Sort events by attack_start time ---------------------------------
    def sort_key(e):
        ts  = e.get("meta_features", {}).get("timestamp", {})
        dt  = parse_attack_start(ts.get("attack_start") or ts.get("detection"))
        return dt or datetime.max

    sorted_events = sorted(events, key=sort_key)

    stem_to_idx = {e["_stem"]: i for i, e in enumerate(sorted_events)}

    edge_map: dict[tuple[int,int], float] = {}

    for i, e in enumerate(sorted_events):
        rels = e.get("meta_features", {}).get("related_events",[])
        for rel in rels:
            name = rel.get("id_or_name", "").strip()
            conf = parse_confidence_value(rel.get("confidence", 1.0))
            if name in stem_to_idx:
                j = stem_to_idx[name]
                key = (min(i, j), max(i, j))
                edge_map[key] = max(edge_map.get(key, 0.0), conf)

    edges =[(a, b, c) for (a, b), c in edge_map.items()]

    def thread_key(e):
        dm  = e.get("diamond_model", {})
        adv = dm.get("adversary", {}).get("name") or "Unknown Adversary"
        assets = dm.get("victim", {}).get("assets",[])
        vic = assets[0].get("asset", "Unknown Victim") if assets else "Unknown Victim"
        return (adv, vic)

    seen_threads: list[tuple] =[]
    for e in sorted_events:
        tk = thread_key(e)
        if tk not in seen_threads:
            seen_threads.append(tk)
    
    seen_threads.sort(key=lambda tk: tk[0].lower())

    thread_idx = {tk: i for i, tk in enumerate(seen_threads)}
    n_threads  = len(seen_threads)

    ROW_H    = 100    
    COL_W    = 140   
    LEFT_W   = 350   
    TOP_H    = 72    
    NODE_R   = 16    
    FONT     = "Share Tech Mono, monospace"
    LEGEND_H = 48    

    total_w  = LEFT_W + n_threads * COL_W + 40
    total_h  = TOP_H  + len(KILL_CHAIN_PHASES) * ROW_H + LEGEND_H

    def event_xy(i: int) -> tuple[float, float]:
        e   = sorted_events[i]
        tk  = thread_key(e)
        col = thread_idx[tk]
        phase = canonical_phase(
            e.get("meta_features", {}).get("phase", {}).get("kill_chain_phase")
        )
        row = PHASE_ROW.get(phase.lower() if phase else "", 0)
        cx  = LEFT_W + col * COL_W + COL_W // 2
        cy  = TOP_H  + row * ROW_H + ROW_H // 2
        return cx, cy

    adv_groups: list[tuple[str, int, int]] =[]
    i = 0
    while i < n_threads:
        adv_name = seen_threads[i][0]
        j = i
        while j < n_threads and seen_threads[j][0] == adv_name:
            j += 1
        adv_groups.append((adv_name, i, j - 1))
        i = j

    parts: list[str] =[]

    parts.append(
        f'<svg viewBox="0 0 {total_w} {total_h}" '
        f'xmlns="http://www.w3.org/2000/svg" '
        f'class="thread-svg" style="width:100%;max-width:{total_w}px;">'
    )

    parts.append("""
  <defs>
    <marker id="arrow-solid" markerWidth="8" markerHeight="8"
            refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#00ff88"/>
    </marker>
    <marker id="arrow-dashed" markerWidth="8" markerHeight="8"
            refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#ffcc00"/>
    </marker>
    <marker id="arrow-dotted" markerWidth="8" markerHeight="8"
            refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#ff8800"/>
    </marker>
  </defs>""")

    parts.append(f'  <rect width="{total_w}" height="{total_h}" fill="#07090f"/>')

    for row_i, phase in enumerate(KILL_CHAIN_PHASES):
        y   = TOP_H + row_i * ROW_H
        bg  = "#0b0f1c" if row_i % 2 == 0 else "#07090f"
        parts.append(f'  <rect class="grid-row-bg" x="0" y="{y}" width="{total_w}" height="{ROW_H}" fill="{bg}"/>')

    for col_i in range(n_threads + 1):
        x = LEFT_W + col_i * COL_W
        parts.append(f'  <line x1="{x}" y1="0" x2="{x}" y2="{total_h}" stroke="#1a2238" stroke-width="1"/>')
    parts.append(f'  <line x1="{LEFT_W}" y1="0" x2="{LEFT_W}" y2="{total_h}" stroke="#2a3455" stroke-width="1.5"/>')
    for row_i in range(len(KILL_CHAIN_PHASES) + 1):
        y = TOP_H + row_i * ROW_H
        parts.append(f'  <line x1="0" y1="{y}" x2="{total_w}" y2="{y}" stroke="#1a2238" stroke-width="1"/>')
    parts.append(f'  <line x1="{LEFT_W}" y1="36" x2="{total_w}" y2="36" stroke="#1a2238" stroke-width="1"/>')

    for adv_name, c_start, c_end in adv_groups:
        x1 = LEFT_W + c_start * COL_W
        x2 = LEFT_W + (c_end + 1) * COL_W
        cx = (x1 + x2) / 2
        parts.append(f'  <rect x="{x1}" y="0" width="{x2 - x1}" height="36" fill="#0d1530"/>')
        parts.append(f'  <text x="{cx}" y="23" text-anchor="middle" font-family="{FONT}" font-size="14" fill="#00d4ff" letter-spacing="1">{h(adv_name)}</text>')

    for col_i, (adv_name, vic_label) in enumerate(seen_threads):
        cx = LEFT_W + col_i * COL_W + COL_W // 2
        parts.append(f'  <rect x="{LEFT_W + col_i * COL_W}" y="36" width="{COL_W}" height="{TOP_H - 36}" fill="#0b0f1c"/>')
        parts.append(f'  <text x="{cx}" y="{36 + (TOP_H - 36) // 2 + 5}" text-anchor="middle" font-family="{FONT}" font-size="14" fill="#4a7a9b">{h(truncate(vic_label, 16))}</text>')

    for row_i, phase in enumerate(KILL_CHAIN_PHASES):
        y = TOP_H + row_i * ROW_H + ROW_H // 2
        parts.append(f'  <text x="{LEFT_W - 25}" y="{y + 5}" text-anchor="end" font-family="{FONT}" font-size="16" fill="#b8c8e0">{h(phase)}</text>')

    parts.append(f'  <text x="10" y="20" font-family="{FONT}" font-size="12" fill="#445566" letter-spacing="2">THREAD</text>')

    for (i, j, conf) in edges:
        x1, y1 = event_xy(i)
        x2, y2 = event_xy(j)

        import math
        dx, dy = x2 - x1, y2 - y1
        dist   = math.hypot(dx, dy)
        if dist < 1: continue
        ux, uy  = dx / dist, dy / dist
        margin  = NODE_R + 4
        sx, sy  = x1 + ux * margin, y1 + uy * margin
        ex, ey  = x2 - ux * margin, y2 - uy * margin

        dash    = _arc_style(conf)
        color   = _arc_color(conf)
        da_attr = "" if dash == "none" else f'stroke-dasharray="{dash}"'
        marker_id = "arrow-solid" if conf >= 1.0 else "arrow-dashed" if conf >= 0.5 else "arrow-dotted"

        if abs(x1 - x2) < 5:
            parts.append(f'  <line x1="{sx:.1f}" y1="{sy:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" stroke="{color}" stroke-width="1.8" {da_attr} marker-end="url(#{marker_id})"/>')
        else:
            mid_x, mid_y = (sx + ex) / 2, (sy + ey) / 2
            perp_x, perp_y = -(ey - sy), (ex - sx)
            plen   = math.hypot(perp_x, perp_y) or 1
            bend   = 40
            cpx, cpy = mid_x + (perp_x / plen) * bend, mid_y + (perp_y / plen) * bend
            parts.append(f'  <path d="M {sx:.1f},{sy:.1f} Q {cpx:.1f},{cpy:.1f} {ex:.1f},{ey:.1f}" fill="none" stroke="{color}" stroke-width="1.8" {da_attr} marker-end="url(#{marker_id})"/>')

    for i, e in enumerate(sorted_events):
        cx, cy  = event_xy(i)
        inc_id  = e.get("incident", {}).get("id") or e["_stem"]
        label   = truncate(str(i + 1), 3)
        ongoing = e.get("response", {}).get("ongoing") is True
        r = NODE_R
        pts = f"{cx},{cy-r} {cx+r},{cy} {cx},{cy+r} {cx-r},{cy}"
        stroke_color = "#ff4455" if ongoing else "#00d4ff"
        fill_color   = "rgba(255,68,85,0.15)" if ongoing else "#0f1526"
        parts.append(f'  <polygon points="{pts}" fill="{fill_color}" stroke="{stroke_color}" stroke-width="1.5"/>')
        parts.append(f'  <text x="{cx}" y="{cy + 4}" text-anchor="middle" font-family="{FONT}" font-size="14" fill="#b8c8e0">{label}</text>')
        parts.append(f'  <title>{h(inc_id)}</title>')

    legend_items =[
        ("solid",  "#00ff88", "none", "none",   "Confirmed (1.0)"),
        ("dashed", "#ffcc00", "8,5",  "none",   "Probable (≥0.5)"),
        ("dotted", "#ff8800", "3,4",  "none",   "Hypothesised (<0.5)"),
        ("ongoing","#ff4455", "none", "ongoing","Ongoing event"),
    ]

    legend_top = total_h - LEGEND_H
    parts.append(f'  <line x1="0" y1="{legend_top}" x2="{total_w}" y2="{legend_top}" stroke="#2a3455" stroke-width="1"/>')

    n_items   = len(legend_items)
    slot_w    = total_w / n_items
    line_len  = 30
    line_y    = legend_top + LEGEND_H // 2
    text_y    = line_y + 5

    for item_i, (tag, color, da, shape, label_text) in enumerate(legend_items):
        item_cx = slot_w * item_i + slot_w / 2
        sym_x1  = item_cx - line_len / 2 - 5
        sym_x2  = item_cx - line_len / 2 - 5 + line_len
        tx      = sym_x2 + 8
        if shape == "ongoing":
            r2 = 9
            pts = (f"{item_cx - line_len/2 - 5 + r2},{line_y - r2} "
                   f"{item_cx - line_len/2 - 5 + r2*2},{line_y} "
                   f"{item_cx - line_len/2 - 5 + r2},{line_y + r2} "
                   f"{item_cx - line_len/2 - 5},{line_y}")
            parts.append(f'  <polygon points="{pts}" fill="rgba(255,68,85,0.15)" stroke="{color}" stroke-width="2"/>')
        else:
            da_attr = "" if da == "none" else f'stroke-dasharray="{da}"'
            parts.append(f'  <line x1="{sym_x1:.1f}" y1="{line_y}" x2="{sym_x2:.1f}" y2="{line_y}" stroke="{color}" stroke-width="3" {da_attr}/>')
        parts.append(f'  <text x="{tx:.1f}" y="{text_y}" font-family="{FONT}" font-size="14" fill="#b8c8e0">{h(label_text)}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def build_activity_thread_svg_interactive(events: list[dict], sorted_events: list[dict], stem_to_event_idx: dict) -> str:
    def sort_key(e):
        ts = e.get("meta_features", {}).get("timestamp", {})
        dt = parse_attack_start(ts.get("attack_start") or ts.get("detection"))
        return dt or datetime.max
    
    sorted_ev_local = sorted(events, key=sort_key)
    for e in sorted_ev_local: sorted_events.append(e)
    stem_to_idx = {e["_stem"]: i for i, e in enumerate(sorted_ev_local)}
    
    edge_map = {}
    for i, e in enumerate(sorted_ev_local):
        for rel in e.get("meta_features", {}).get("related_events",[]):
            name = rel.get("id_or_name", "").strip()
            conf = parse_confidence_value(rel.get("confidence", 1.0))
            if name in stem_to_idx:
                j = stem_to_idx[name]
                key = (min(i, j), max(i, j))
                edge_map[key] = max(edge_map.get(key, 0.0), conf)

    def thread_key(e):
        dm = e.get("diamond_model", {})
        adv = dm.get("adversary", {}).get("name") or "Unknown Adversary"
        assets = dm.get("victim", {}).get("assets", [])
        vic = assets[0].get("asset", "Unknown Victim") if assets else "Unknown Victim"
        return (adv, vic)

    seen_threads =[]
    for e in sorted_ev_local:
        tk = thread_key(e)
        if tk not in seen_threads: seen_threads.append(tk)
        
    seen_threads.sort(key=lambda tk: tk[0].lower())

    thread_idx = {tk: i for i, tk in enumerate(seen_threads)}
    n_threads = len(seen_threads)

    # UI DIMENSIONS
    ROW_H = 120
    COL_W = 280
    LEFT_W = 380
    TOP_H = 150
    NODE_R = 28  
    FONT = "Share Tech Mono, monospace"
    
    content_w = LEFT_W + n_threads * COL_W + 50
    total_w = max(1400, content_w)
    total_h = TOP_H + len(KILL_CHAIN_PHASES) * ROW_H + 150

    def get_col_row(i):
        e = sorted_ev_local[i]
        tk = thread_key(e)
        col = thread_idx[tk]
        p = canonical_phase(e.get("meta_features", {}).get("phase", {}).get("kill_chain_phase"))
        row = PHASE_ROW.get(p.lower() if p else "", 6)
        return col, row

    def get_xy(i):
        col, row = get_col_row(i)
        return LEFT_W + col * COL_W + COL_W // 2, TOP_H + row * ROW_H + ROW_H // 2

    adv_groups: list[tuple[str, int, int]] =[]
    i = 0
    while i < n_threads:
        adv_name = seen_threads[i][0]
        j = i
        while j < n_threads and seen_threads[j][0] == adv_name:
            j += 1
        adv_groups.append((adv_name, i, j - 1))
        i = j

    parts =[f'<svg viewBox="0 0 {total_w} {total_h}" xmlns="http://www.w3.org/2000/svg" class="thread-svg">']

    parts.append(f"""  <defs>
    <marker id="arr-solid"  markerWidth="12" markerHeight="8" refX="11" refY="4" orient="auto" markerUnits="userSpaceOnUse">
      <polygon points="0 0, 12 4, 0 8" fill="#00ff88"/>
    </marker>
    <marker id="arr-dashed" markerWidth="12" markerHeight="8" refX="11" refY="4" orient="auto" markerUnits="userSpaceOnUse">
      <polygon points="0 0, 12 4, 0 8" fill="#ffcc00"/>
    </marker>
    <marker id="arr-dotted" markerWidth="12" markerHeight="8" refX="11" refY="4" orient="auto" markerUnits="userSpaceOnUse">
      <polygon points="0 0, 12 4, 0 8" fill="#ff8800"/>
    </marker>
    <filter id="arc-glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="2.5" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="node-glow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur stdDeviation="4" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>""")

    parts.append(f'<rect width="100%" height="100%" fill="#07090f"/>')

    # Grid rows
    for i, phase in enumerate(KILL_CHAIN_PHASES):
        y = TOP_H + i * ROW_H
        bg = "#0b0f1c" if i % 2 == 0 else "#07090f"
        parts.append(f'  <rect class="grid-row-bg" x="0" y="{y}" width="{total_w}" height="{ROW_H}" fill="{bg}"/>')
        parts.append(f'  <text x="{LEFT_W - 30}" y="{y + ROW_H//2 + 8}" text-anchor="end" font-family="{FONT}" font-size="20" font-weight="bold" fill="#adbcd4">{h(phase)}</text>')

    # Column Headers (Victims and columns)
    for col_i, (adv, vic) in enumerate(seen_threads):
        cx = LEFT_W + col_i * COL_W + COL_W // 2
        parts.append(f'  <g class="apt-col-header" data-orig-col="{col_i}" data-adv="{h(adv)}">')
        parts.append(f'  <rect x="{LEFT_W + col_i * COL_W}" y="42" width="{COL_W}" height="{total_h - 42}" fill="rgba(0,212,255,0.02)"/>')
        v_lines = svg_wrap(vic, width_chars=25)
        for row_idx, line in enumerate(v_lines):
            parts.append(f'  <text x="{cx}" y="{76 + row_idx*20}" text-anchor="middle" font-family="{FONT}" font-size="14" fill="#5a7a9b">{h(line)}</text>')
        parts.append('  </g>')

    # Adversary Groups (Top bands spanning columns)
    for adv_name, c_start, c_end in adv_groups:
        x1 = LEFT_W + c_start * COL_W
        x2 = LEFT_W + (c_end + 1) * COL_W
        cx = (x1 + x2) / 2
        parts.append(f'  <g class="apt-adv-band" data-adv="{h(adv_name)}" data-orig-start="{c_start}" data-orig-end="{c_end}">')
        parts.append(f'  <rect x="{x1}" y="0" width="{x2 - x1}" height="42" fill="#0d1530"/>')
        parts.append(f'  <text x="{cx}" y="{28}" text-anchor="middle" font-family="{FONT}" font-size="20" font-weight="bold" fill="#00d4ff" letter-spacing="1">{h(adv_name)}</text>')
        parts.append('  </g>')

    import math
    SHRINK = NODE_R + 3   

    for (i, j), conf in edge_map.items():
        x1, y1 = get_xy(i)
        x2, y2 = get_xy(j)
        color  = "#00ff88" if conf >= 1.0 else ("#ffcc00" if conf >= 0.5 else "#ff8800")
        marker = "arr-solid" if conf >= 1.0 else ("arr-dashed" if conf >= 0.5 else "arr-dotted")
        da_attr = "" if conf >= 1.0 else (
            ' stroke-dasharray="10,6"' if conf >= 0.5 else ' stroke-dasharray="4,5"'
        )

        dx, dy = x2 - x1, y2 - y1
        dist   = math.hypot(dx, dy)
        if dist < 1: continue
        ux, uy = dx / dist, dy / dist

        sx, sy = x1 + ux * SHRINK, y1 + uy * SHRINK
        ex, ey = x2 - ux * SHRINK, y2 - uy * SHRINK

        src_col, src_row = get_col_row(i)
        dst_col, dst_row = get_col_row(j)
        adv_i = sorted_ev_local[i].get("diamond_model", {}).get("adversary", {}).get("name") or "Unknown Adversary"
        adv_j = sorted_ev_local[j].get("diamond_model", {}).get("adversary", {}).get("name") or "Unknown Adversary"
        
        parts.append(f'  <g class="apt-el-edge" data-adv-src="{h(adv_i)}" data-adv-dst="{h(adv_j)}" data-src-col="{src_col}" data-src-row="{src_row}" data-dst-col="{dst_col}" data-dst-row="{dst_row}">')

        same_col = abs(x1 - x2) < 5
        if same_col:
            mx, my = (sx + ex) / 2, (sy + ey) / 2
            d_str = f"M {sx:.1f},{sy:.1f} Q {mx:.1f},{my:.1f} {ex:.1f},{ey:.1f}"
        else:
            mx, my    = (sx + ex) / 2, (sy + ey) / 2
            perp_x    = -uy
            perp_y    =  ux
            bend      = min(55, dist * 0.25)
            cpx       = mx + perp_x * bend
            cpy       = my + perp_y * bend
            d_str = f"M {sx:.1f},{sy:.1f} Q {cpx:.1f},{cpy:.1f} {ex:.1f},{ey:.1f}"

        parts.append(
            f'  <path class="edge-path" d="{d_str}" '
            f'fill="none" stroke="{color}" stroke-width="2"{da_attr} opacity="0.9" '
            f'marker-end="url(#{marker})" filter="url(#arc-glow)"/>'
        )
        parts.append('  </g>')

    for i, e in enumerate(sorted_ev_local):
        cx, cy = get_xy(i)
        ong    = e.get("response", {}).get("ongoing") is True
        color  = "#ff4455" if ong else "#00ff88"
        halo_r = NODE_R + 6
        col, row = get_col_row(i)
        adv_name = e.get("diamond_model", {}).get("adversary", {}).get("name") or "Unknown Adversary"
        
        parts.append(f'  <g class="apt-node" data-orig-col="{col}" data-row="{row}" data-adv="{h(adv_name)}">')
        parts.append(
            f'  <polygon points="{cx},{cy-halo_r} {cx+halo_r},{cy} {cx},{cy+halo_r} {cx-halo_r},{cy}" '
            f'fill="{color}" opacity="0.12" filter="url(#node-glow)"/>'
        )
        parts.append(
            f'  <polygon points="{cx},{cy-NODE_R} {cx+NODE_R},{cy} {cx},{cy+NODE_R} {cx-NODE_R},{cy}" '
            f'fill="#0c1220" stroke="{color}" stroke-width="2.5"/>'
        )
        parts.append(
            f'  <text x="{cx}" y="{cy + 7}" text-anchor="middle" '
            f'font-family="{FONT}" font-size="18" font-weight="900" '
            f'fill="#e2e8f0" style="pointer-events:none">{i+1}</text>'
        )
        parts.append('  </g>')

    for i, e in enumerate(sorted_ev_local):
        cx, cy   = get_xy(i)
        orig_idx = stem_to_event_idx[e["_stem"]]
        ong      = e.get("response", {}).get("ongoing") is True
        col, row = get_col_row(i)
        adv_name = e.get("diamond_model", {}).get("adversary", {}).get("name") or "Unknown Adversary"
        
        parts.append(f'  <g class="apt-hit" data-orig-col="{col}" data-row="{row}" data-adv="{h(adv_name)}">')
        parts.append(
            f'  <rect class="map-node-hit" '
            f'x="{cx - NODE_R - 4}" y="{cy - NODE_R - 4}" '
            f'width="{(NODE_R + 4) * 2}" height="{(NODE_R + 4) * 2}" '
            f'fill="transparent" style="cursor:pointer" '
            f'data-idx="{orig_idx}" data-sorted="{i}" '
            f'data-adv="{h(adv_name)}" '
            f'data-ong="{1 if ong else 0}" '
            f'onclick="openDetail({orig_idx})"/>'
        )
        parts.append('  </g>')

    lx, ly = 50, total_h - 60
    leg_data =[ 
        ("#00ff88", "none", "Confirmed (1.0)"), 
        ("#ffcc00", "8,5", "Probable (≥0.5)"), 
        ("#ff8800", "3,4", "Hypothesised (<0.5)"), 
        ("#ff4455", "diamond", "Ongoing event") 
    ]
    for color, dash, txt in leg_data:
        y_center = ly - 7
        if dash == "diamond":
            r2 = 12
            parts.append(f'  <polygon points="{lx+r2},{y_center-r2} {lx+r2*2},{y_center} {lx+r2},{y_center+r2} {lx},{y_center}" fill="rgba(255,68,85,0.2)" stroke="{color}" stroke-width="3"/>')
        else:
            parts.append(f'  <line x1="{lx}" y1="{y_center}" x2="{lx+45}" y2="{y_center}" stroke="{color}" stroke-width="5"{(" stroke-dasharray=" + chr(34) + dash + chr(34)) if dash != "none" else ""}/>')
        
        parts.append(f'  <text x="{lx + 60}" y="{ly}" font-family="{FONT}" font-size="20" font-weight="bold" fill="#e2e8f0">{h(txt)}</text>')
        lx += 310

    import json as _json
    thread_meta =[
        {"adv": adv, "vic": vic, "col": ci}
        for ci, (adv, vic) in enumerate(seen_threads)
    ]
    parts.append(
        f'  <desc id="thread-meta" style="display:none">'
        f'{_json.dumps(thread_meta)}</desc>'
    )

    parts.append("</svg>")
    return "".join(parts)


def event_card_html(event: dict, idx: int) -> str:
    """Retained for library usage (unused directly in HTML generation)"""
    inc  = event.get("incident", {})
    ts   = event.get("meta_features", {}).get("timestamp", {})
    mf   = event.get("meta_features", {})
    dm   = event.get("diamond_model", {})
    resp = event.get("response", {})

    ongoing = resp.get("ongoing")
    if ongoing is True: status = '<span class="tag tag-red">ONGOING</span>'
    elif ongoing is False: status = '<span class="tag tag-green">RESOLVED</span>'
    else: status = '<span class="tag tag-gray">UNKNOWN</span>'

    phase      = mf.get("phase", {}).get("kill_chain_phase") or "—"
    outcome    = mf.get("result", {}).get("outcome") or "—"
    direction  = mf.get("direction", {}).get("value") or "—"
    adv_conf   = dm.get("adversary", {}).get("confidence", "unknown")

    atk_types = mf.get("methodology", {}).get("attack_type",[])
    atk_vecs  = mf.get("methodology", {}).get("attack_vector",[])
    type_tags  = "".join(f'<span class="tag tag-blue">{h(t)}</span>' for t in atk_types) or '<span class="muted">—</span>'
    vec_tags   = "".join(f'<span class="tag tag-purple">{h(v)}</span>' for v in atk_vecs) or '<span class="muted">—</span>'

    cia = mf.get("result", {}).get("cia_impact", {})
    def cia_row(label, key):
        item = cia.get(key, {})
        desc = h(item.get("description") or "—")
        conf = badge(item.get("confidence", "unknown"))
        return f'<tr><td class="row-label">{label}</td><td>{desc}</td><td>{conf}</td></tr>'

    related = mf.get("related_events",[])
    if related:
        rel_items =[]
        for rel in related:
            name = h(rel.get("id_or_name", ""))
            conf_val = rel.get("confidence", 1.0)
            conf = parse_confidence_value(conf_val)
            if conf >= 1.0: style = "color:#00ff88"; line_type = "confirmed"
            elif conf >= 0.5: style = "color:#ffcc00"; line_type = "probable"
            else: style = "color:#ff8800"; line_type = "hypothesised"
            rel_items.append(f'<span class="mono" style="{style}">{name}</span><span class="muted" style="font-size:14px"> ({line_type}, {conf_val})</span>')
        related_html = " &nbsp;·&nbsp; ".join(rel_items)
    else:
        related_html = '<span class="muted">—</span>'

    iocs = dm.get("capability", {}).get("iocs",[])
    ioc_rows = "".join(
        f'<tr><td class="mono">{h(i.get("type",""))}</td>'
        f'<td class="mono wrap">{h(i.get("value",""))}</td>'
        f'<td>{badge(i.get("confidence","unknown"))}</td></tr>'
        for i in iocs
    ) or '<tr><td colspan="3" class="muted">No IoCs recorded</td></tr>'

    assets = dm.get("victim", {}).get("assets",[])
    asset_rows = "".join(
        f'<tr><td>{h(a.get("asset",""))}</td>'
        f'<td>{h(a.get("owner",""))}</td>'
        f'<td>{badge(a.get("confidence","unknown"))}</td></tr>'
        for a in assets
    ) or '<tr><td colspan="3" class="muted">No assets recorded</td></tr>'

    personnel = resp.get("assigned_personnel",[])
    pers_html = " &nbsp;·&nbsp; ".join(
        f'{h(p.get("name",""))} <span class="muted">({h(p.get("role",""))})</span>'
        for p in personnel if p.get("name")
    ) or '<span class="muted">—</span>'

    filename = event.get("_filename", f"event_{idx+1}")

    return f"""
<section class="event-card" id="event-{idx}">
  <div class="card-header">
    <div class="card-title">
      <span class="ev-num">#{idx+1:02d}</span>
      <span class="ev-id">{h(inc.get("id") or filename)}</span>
      {status}
    </div>
    <div class="card-meta">
      <span>Detection: <strong>{h(ts.get("detection") or "—")}</strong></span>
      <span>Attack start: <strong>{h(ts.get("attack_start") or "—")}</strong></span>
      <span>Updated: <strong>{h(inc.get("last_updated") or "—")}</strong></span>
    </div>
  </div>
  <div class="card-body">
    <div class="diamond-col">
        <svg viewBox="-20 -20 540 540" width="100%" class="diamond-svg">
          {diamond_svg(event, idx)}
        </svg>
      <div class="diamond-legend">
        <span class="lg-confirmed">● confirmed</span>
        <span class="lg-probable">● probable</span>
        <span class="lg-possible">● possible</span>
        <span class="lg-unknown">● unknown</span>
      </div>
    </div>
    <div class="detail-col">
      <div class="meta-strip">
        <div class="meta-item"><div class="meta-key">Kill Chain Phase</div><div class="meta-val">{h(phase)}</div></div>
        <div class="meta-item"><div class="meta-key">Result</div><div class="meta-val">{h(outcome)}</div></div>
        <div class="meta-item"><div class="meta-key">Direction</div><div class="meta-val">{h(direction)}</div></div>
        <div class="meta-item"><div class="meta-key">Adversary Conf.</div><div class="meta-val">{badge(adv_conf)}</div></div>
      </div>
      <div class="detail-block">
        <div class="block-title">Attack Type</div>
        <div class="tag-row">{type_tags}</div>
        <div class="block-title" style="margin-top:12px">Attack Vector</div>
        <div class="tag-row">{vec_tags}</div>
      </div>
      <div class="detail-block">
        <div class="block-title">CIA Impact</div>
        <table class="dtable">
          {cia_row("Confidentiality", "confidentiality")}
          {cia_row("Integrity", "integrity")}
          {cia_row("Availability", "availability")}
        </table>
      </div>
      <div class="detail-block">
        <div class="block-title">Related Events (Direct Causal Links)</div>
        <div class="mono" style="font-size:13px;line-height:2">{related_html}</div>
      </div>
      <div class="detail-block">
        <div class="block-title">Assigned Personnel</div>
        <div class="mono" style="font-size:13px">{pers_html}</div>
      </div>
    </div>
  </div>
  <div class="card-footer">
    <div class="footer-col">
      <div class="block-title">Indicators of Compromise</div>
      <table class="dtable">
        <thead><tr><th>Type</th><th>Value</th><th>Confidence</th></tr></thead>
        <tbody>{ioc_rows}</tbody>
      </table>
    </div>
    <div class="footer-col">
      <div class="block-title">Affected Assets</div>
      <table class="dtable">
        <thead><tr><th>Asset</th><th>Owner</th><th>Confidence</th></tr></thead>
        <tbody>{asset_rows}</tbody>
      </table>
    </div>
  </div>
</section>"""


# ---------------------------------------------------------------------------
# HTML: full report page
# ---------------------------------------------------------------------------

def generate_html(events: list[dict]) -> str:
    now            = datetime.now().strftime("%Y-%m-%d %H:%M")
    total          = len(events)
    ongoing_count  = sum(1 for e in events if e.get("response", {}).get("ongoing") is True)

    stem_to_event_idx = {e["_stem"]: i for i, e in enumerate(events)}

    def make_summary_row(i, e):
        inc  = e.get("incident", {})
        ts   = e.get("meta_features", {}).get("timestamp", {})
        dm   = e.get("diamond_model", {})
        mf   = e.get("meta_features", {})
        resp = e.get("response", {})
        ongoing = resp.get("ongoing")

        if ongoing is True:
            st = '<td><span class="tag tag-red">ONGOING</span></td>'
            row_class = "row-ongoing"
        elif ongoing is False:
            st = '<td><span class="tag tag-green">resolved</span></td>'
            row_class = "row-resolved"
        else:
            st = '<td><span class="muted">?</span></td>'
            row_class = "row-resolved"

        atk  = truncate(", ".join(mf.get("methodology", {}).get("attack_type",[])), 40) or "—"
        vic  = truncate(", ".join(
                   a.get("asset", "") for a in dm.get("victim", {}).get("assets",[])
                   if a.get("asset")), 30) or "—"
        adv  = dm.get("adversary", {}).get("name") or "—"
        iocs = len(dm.get("capability", {}).get("iocs",[]))
        n_related = len(mf.get("related_events",[]))

        return f"""
        <tr class="{row_class}" onclick="openDetail({i})">
          <td class="mono">{i+1:02d}</td>
          <td class="mono">{h(inc.get("id",""))}</td>
          <td class="mono">{h(ts.get("detection") or "—")}</td>
          {st}
          <td>{h(adv)}</td>
          <td>{h(atk)}</td>
          <td>{h(vic)}</td>
          <td class="center mono">{iocs}</td>
          <td class="center mono">{n_related}</td>
        </tr>"""

    summary_rows = "\n".join(make_summary_row(i, e) for i, e in enumerate(events))

    hover_svgs = ""
    for i, e in enumerate(events):
        hover_svgs += (
            f'<div id="hover-svg-{i}" style="display:none">'
            f'<svg viewBox="-40 10 580 480" xmlns="http://www.w3.org/2000/svg" '
            f'width="100%" height="100%">{diamond_svg(e, i, is_hover=True)}</svg>'
            f'</div>\n'
        )

    all_adv_names =[]
    for e in events:
        name = e.get("diamond_model", {}).get("adversary", {}).get("name") or "Unknown Adversary"
        if name not in all_adv_names:
            all_adv_names.append(name)

    apt_filter_btns = "\n".join(
        f'<button class="apt-btn active" data-adv="{h(name)}" '
        f'onclick="toggleApt(this)">{h(name)}</button>'
        for name in all_adv_names
    )

    sorted_buf: list[dict] =[]
    thread_svg = build_activity_thread_svg_interactive(events, sorted_buf, stem_to_event_idx)

    def event_detail_panel(event: dict, idx: int) -> str:
        inc  = event.get("incident", {})
        ts   = event.get("meta_features", {}).get("timestamp", {})
        mf   = event.get("meta_features", {})
        dm   = event.get("diamond_model", {})
        resp = event.get("response", {})

        ongoing = resp.get("ongoing")
        if ongoing is True: status = '<span class="tag tag-red">ONGOING</span>'
        elif ongoing is False: status = '<span class="tag tag-green">RESOLVED</span>'
        else: status = '<span class="tag tag-gray">UNKNOWN</span>'

        phase      = mf.get("phase", {}).get("kill_chain_phase") or "—"
        outcome    = mf.get("result", {}).get("outcome") or "—"
        direction  = mf.get("direction", {}).get("value") or "—"
        adv_conf   = dm.get("adversary", {}).get("confidence", "unknown")

        atk_types = mf.get("methodology", {}).get("attack_type",[])
        atk_vecs  = mf.get("methodology", {}).get("attack_vector",[])
        type_tags  = "".join(f'<span class="tag tag-blue">{h(t)}</span>' for t in atk_types) or '<span class="muted">—</span>'
        vec_tags   = "".join(f'<span class="tag tag-purple">{h(v)}</span>' for v in atk_vecs) or '<span class="muted">—</span>'

        cia = mf.get("result", {}).get("cia_impact", {})
        def cia_row(label, key):
            item = cia.get(key, {})
            desc = h(item.get("description") or "—")
            conf = badge(item.get("confidence", "unknown"))
            return f'<tr><td class="row-label">{label}</td><td>{desc}</td><td>{conf}</td></tr>'

        related = mf.get("related_events", [])
        if related:
            rel_items =[]
            for rel in related:
                name = h(rel.get("id_or_name", ""))
                conf_val = rel.get("confidence", 1.0)
                conf = parse_confidence_value(conf_val)
                if conf >= 1.0: style = "color:#00ff88"; line_type = "confirmed"
                elif conf >= 0.5: style = "color:#ffcc00"; line_type = "probable"
                else: style = "color:#ff8800"; line_type = "hypothesised"
                rel_items.append(f'<span class="mono" style="{style}">{name}</span><span class="muted" style="font-size:14px"> ({line_type}, {conf_val})</span>')
            related_html = " &nbsp;·&nbsp; ".join(rel_items)
        else:
            related_html = '<span class="muted">—</span>'

        iocs = dm.get("capability", {}).get("iocs",[])
        ioc_rows = "".join(
            f'<tr><td class="mono">{h(i.get("type",""))}</td>'
            f'<td class="mono wrap">{h(i.get("value",""))}</td>'
            f'<td>{badge(i.get("confidence","unknown"))}</td></tr>'
            for i in iocs
        ) or '<tr><td colspan="3" class="muted">No IoCs recorded</td></tr>'

        assets = dm.get("victim", {}).get("assets",[])
        asset_rows = "".join(
            f'<tr><td>{h(a.get("asset",""))}</td>'
            f'<td>{h(a.get("owner",""))}</td>'
            f'<td>{badge(a.get("confidence","unknown"))}</td></tr>'
            for a in assets
        ) or '<tr><td colspan="3" class="muted">No assets recorded</td></tr>'

        personnel = resp.get("assigned_personnel",[])
        pers_html = " &nbsp;·&nbsp; ".join(
            f'{h(p.get("name",""))} <span class="muted">({h(p.get("role",""))})</span>'
            for p in personnel if p.get("name")
        ) or '<span class="muted">—</span>'

        filename = event.get("_filename", f"event_{idx+1}")

        return f"""
<div class="detail-panel" id="detail-panel-{idx}" style="display:none">
  <section class="event-card" id="event-{idx}">
    <div class="card-header">
      <div class="card-title">
        <span class="ev-num">#{idx+1:02d}</span>
        <span class="ev-id">{h(inc.get("id") or filename)}</span>
        {status}
      </div>
      <div style="display:flex;align-items:center;gap:16px">
        <div class="card-meta">
          <span>Detection: <strong>{h(ts.get("detection") or "—")}</strong></span>
          <span>Attack start: <strong>{h(ts.get("attack_start") or "—")}</strong></span>
          <span>Updated: <strong>{h(inc.get("last_updated") or "—")}</strong></span>
        </div>
        <button class="close-panel-btn" onclick="closeDetail({idx})" title="Close">✕</button>
      </div>
    </div>
    <div class="card-body">
      <div class="diamond-col">
        <svg viewBox="-20 -20 540 540" width="100%" class="diamond-svg">
          {diamond_svg(event, idx)}
        </svg>
        <div class="diamond-legend">
          <span class="lg-confirmed">● confirmed</span>
          <span class="lg-probable">● probable</span>
          <span class="lg-possible">● possible</span>
          <span class="lg-unknown">● unknown</span>
        </div>
      </div>
      <div class="detail-col">
        <div class="meta-strip">
          <div class="meta-item"><div class="meta-key">Kill Chain Phase</div><div class="meta-val">{h(phase)}</div></div>
          <div class="meta-item"><div class="meta-key">Result</div><div class="meta-val">{h(outcome)}</div></div>
          <div class="meta-item"><div class="meta-key">Direction</div><div class="meta-val">{h(direction)}</div></div>
          <div class="meta-item"><div class="meta-key">Adversary Conf.</div><div class="meta-val">{badge(adv_conf)}</div></div>
        </div>
        <div class="detail-block">
          <div class="block-title">Attack Type</div>
          <div class="tag-row">{type_tags}</div>
          <div class="block-title" style="margin-top:12px">Attack Vector</div>
          <div class="tag-row">{vec_tags}</div>
        </div>
        <div class="detail-block">
          <div class="block-title">CIA Impact</div>
          <table class="dtable">
            {cia_row("Confidentiality", "confidentiality")}
            {cia_row("Integrity", "integrity")}
            {cia_row("Availability", "availability")}
          </table>
        </div>
        <div class="detail-block">
          <div class="block-title">Related Events (Direct Causal Links)</div>
          <div class="mono" style="font-size:13px;line-height:2">{related_html}</div>
        </div>
        <div class="detail-block">
          <div class="block-title">Assigned Personnel</div>
          <div class="mono" style="font-size:13px">{pers_html}</div>
        </div>
      </div>
    </div>
    <div class="card-footer">
      <div class="footer-col">
        <div class="block-title">Indicators of Compromise</div>
        <table class="dtable">
          <thead><tr><th>Type</th><th>Value</th><th>Confidence</th></tr></thead>
          <tbody>{ioc_rows}</tbody>
        </table>
      </div>
      <div class="footer-col">
        <div class="block-title">Affected Assets</div>
        <table class="dtable">
          <thead><tr><th>Asset</th><th>Owner</th><th>Confidence</th></tr></thead>
          <tbody>{asset_rows}</tbody>
        </table>
      </div>
    </div>
  </section>
</div>"""

    all_detail_panels = "\n".join(event_detail_panel(e, i) for i, e in enumerate(events))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Diamond Model — Intel Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
/* ─── Design tokens ───────────────────────────────────────────── */
:root {{
  --bg:        #07090f;
  --bg2:       #0b0f1c;
  --bg3:       #0f1526;
  --border:    #1a2238;
  --accent:    #00d4ff;
  --text:      #b8c8e0;
  --dim:       #8a9bb8;
  --mono:      'Share Tech Mono', monospace;
  --sans:      'Barlow Condensed', sans-serif;
  --confirmed: #00ff88;
  --probable:  #ffcc00;
  --possible:  #ff8800;
  --unknown:   #445566;
  --red:       #ff4455;
  --blue:      #66aaff;
  --purple:    #bb88ff;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: #e2e8f0;
  font-family: var(--sans);
  font-size: 18px;
  line-height: 1.55;
}}

/* ─── Page header ─────────────────────────────────────────────── */
.page-header {{
  background: linear-gradient(160deg, #07090f 0%, #0d1530 100%);
  border-bottom: 1px solid var(--border);
  padding: 36px 56px 28px;
  position: relative; overflow: hidden;
}}
.page-header::before {{
  content:''; position:absolute; inset:0;
  background: repeating-linear-gradient(
    -45deg, transparent, transparent 38px,
    rgba(0,212,255,0.018) 38px, rgba(0,212,255,0.018) 39px
  );
  pointer-events: none;
}}
.page-header h1 {{
  font-size: 32px; font-weight: 700;
  letter-spacing: 5px; text-transform: uppercase;
  color: var(--accent); margin-bottom: 5px;
}}
.page-header .subtitle {{
  font-family: var(--mono); font-size: 16px;
  color: var(--dim); letter-spacing: 2px;
}}
.hdr-stats {{
  position: absolute; right: 56px; top: 50%;
  transform: translateY(-50%);
  display: flex; gap: 40px;
  font-family: var(--mono);
}}
.stat {{ text-align: center; }}
.stat-n {{ font-size: 48px; font-weight: 700; color: var(--accent); line-height: 1; }}
.stat-n.red {{ color: var(--red); }}
.stat-l {{ font-size: 16px; color: var(--dim); letter-spacing: 1.5px; margin-top: 2px; }}

/* ─── Main ────────────────────────────────────────────────────── */
main {{ max-width: 1440px; margin: 0 auto; padding: 36px 40px; }}
.section-label {{
  font-size: 16px; font-weight: 600;
  letter-spacing: 3px; text-transform: uppercase;
  color: var(--dim); padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 16px;
}}
.section-header {{
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 16px; padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}}
.section-header .section-label {{ margin-bottom: 0; padding-bottom: 0; border-bottom: none; }}

/* ─── APT filter bar ──────────────────────────────────────────── */
.apt-filter-bar {{
  display: flex; align-items: center; flex-wrap: wrap; gap: 8px;
  margin-bottom: 12px;
}}
.apt-filter-label {{
  font-family: var(--mono); font-size: 12px; letter-spacing: 2px;
  color: var(--dim); text-transform: uppercase; margin-right: 4px;
}}
.apt-btn {{
  font-family: var(--mono); font-size: 13px; letter-spacing: 1px;
  padding: 4px 12px; cursor: pointer; border-radius: 2px;
  border: 1px solid var(--border);
  background: var(--bg3); color: var(--dim);
  transition: all 0.15s;
}}
.apt-btn.active {{
  background: rgba(0,212,255,0.08);
  color: var(--accent); border-color: var(--accent);
}}
.apt-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
.apt-btn-all {{
  font-family: var(--mono); font-size: 11px; letter-spacing: 1px;
  padding: 3px 8px; cursor: pointer; border-radius: 2px;
  border: 1px solid var(--border);
  background: none; color: var(--dim);
  transition: all 0.15s; margin-left: 4px;
}}
.apt-btn-all:hover {{ color: var(--text); border-color: var(--dim); }}

/* ─── Activity thread ─────────────────────────────────────────── */
.thread-wrap {{
  overflow-x: auto;
  overflow-y: visible;
  margin-bottom: 52px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--bg);
  box-shadow: 0 0 0 1px rgba(0,212,255,0.07), 0 6px 36px rgba(0,0,0,0.5);
}}
.thread-svg {{ display: block; }}
.apt-el, .apt-el-edge {{ transition: opacity 0.25s ease; }}

/* ─── Node hover popup ────────────────────────────────────────── */
.node-hover-popup {{
  position: fixed;
  width: 440px; height: 380px;
  background: #04060e;
  border-radius: 4px;
  pointer-events: none;
  z-index: 9999;
  transition: opacity 0.14s ease;
  display: flex; flex-direction: column;
}}
.node-hover-popup.ong {{ --nhp-accent: var(--red); }}
.node-hover-popup:not(.ong) {{ --nhp-accent: var(--accent); }}

.nhp-bracket {{
  position: absolute; width: 16px; height: 16px;
  border-color: var(--nhp-accent); border-style: solid;
}}
.nhp-tl {{ top: 0; left: 0;  border-width: 2px 0 0 2px; }}
.nhp-tr {{ top: 0; right: 0; border-width: 2px 2px 0 0; }}
.nhp-bl {{ bottom: 0; left: 0;  border-width: 0 0 2px 2px; }}
.nhp-br {{ bottom: 0; right: 0; border-width: 0 2px 2px 0; }}

.nhp-header {{
  padding: 10px 16px 6px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px;
  flex-shrink: 0;
}}
.nhp-num {{ font-family: var(--mono); font-size: 11px; color: var(--dim); }}
.nhp-id {{
  font-family: var(--mono); font-size: 13px;
  color: var(--nhp-accent); letter-spacing: 0.5px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  flex: 1;
}}
.nhp-status {{
  font-family: var(--mono); font-size: 11px;
  padding: 1px 6px; border-radius: 2px; border: 1px solid;
  flex-shrink: 0;
}}
.nhp-status.ong {{ color: var(--red);       border-color: var(--red);       background: rgba(255,68,85,.08); }}
.nhp-status.res {{ color: var(--confirmed); border-color: var(--confirmed); background: rgba(0,255,136,.06); }}
.nhp-status.unk {{ color: var(--dim);       border-color: var(--border); }}

.nhp-diamond {{
  flex: 1;
  min-height: 0;
  padding: 4px 8px;
}}
.nhp-diamond svg {{
  width: 100%; height: 100%;
  overflow: visible;
}}
.nhp-click-hint {{
  text-align: center; padding: 5px 0 8px;
  font-family: var(--mono); font-size: 11px; letter-spacing: 1px;
  color: var(--dim); flex-shrink: 0;
}}

/* ─── Summary table ───────────────────────────────────────────── */
.sum-table {{
  width: 100%; border-collapse: collapse;
  font-size: 16px; margin-bottom: 52px;
}}
.sum-table thead tr {{
  background: var(--bg3);
  border-bottom: 2px solid var(--accent);
}}
.sum-table th {{
  padding: 10px 16px; text-align: left;
  font-size: 16px; letter-spacing: 2px;
  color: var(--accent); font-weight: 600; font-family: var(--sans);
}}
.sum-table tbody tr {{
  border-bottom: 1px solid var(--border);
  cursor: pointer; transition: background 0.12s;
}}
.sum-table tbody tr:hover {{ background: var(--bg3); }}
.sum-table td {{ padding: 9px 16px; vertical-align: middle; }}

.toggle-btn {{
  font-family: var(--mono); font-size: 16px;
  letter-spacing: 1.5px; text-transform: uppercase;
  background: var(--bg3); color: var(--dim);
  border: 1px solid var(--border);
  padding: 5px 12px; cursor: pointer;
  border-radius: 2px; transition: all 0.15s;
}}
.toggle-btn:hover {{ color: var(--accent); border-color: var(--accent); }}
.toggle-btn.active {{ color: var(--accent); border-color: var(--accent); background: rgba(0,212,255,0.06); }}

/* ─── Event cards ─────────────────────────────────────────────── */
.event-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 3px;
  margin-bottom: 36px;
  overflow: hidden;
  transition: border-color 0.2s;
}}
.event-card:hover {{ border-color: rgba(0,212,255,0.25); }}

.card-header {{
  padding: 14px 24px;
  background: var(--bg3);
  border-bottom: 1px solid var(--border);
  display: flex; justify-content: space-between;
  align-items: center; flex-wrap: wrap; gap: 8px;
}}
.card-title {{ display: flex; align-items: center; gap: 12px; }}
.ev-num {{ font-family: var(--mono); font-size: 16px; color: var(--dim); }}
.ev-id  {{ font-family: var(--mono); font-size: 18px; color: var(--accent); letter-spacing: 1px; }}
.card-meta {{
  font-family: var(--mono); font-size: 16px; color: var(--dim);
  display: flex; gap: 24px; flex-wrap: wrap;
}}
.card-meta strong {{ color: #e2e8f0; }}

.close-panel-btn {{
  font-family: var(--mono); font-size: 16px;
  background: none; border: 1px solid var(--border);
  color: var(--dim); cursor: pointer;
  width: 28px; height: 28px; border-radius: 2px;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.12s; flex-shrink: 0;
}}
.close-panel-btn:hover {{ color: var(--red); border-color: var(--red); }}

.card-body {{
  display: grid;
  grid-template-columns: 400px 1fr;
  border-bottom: 1px solid var(--border);
}}
.diamond-col {{
  padding: 24px 20px;
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column; align-items: center;
  background: radial-gradient(ellipse at center,
    rgba(0,212,255,0.04) 0%, transparent 68%);
}}
.diamond-svg {{ width: 100%; max-width: 360px; }}
.diamond-legend {{
  display: flex; flex-wrap: wrap; gap: 10px;
  justify-content: center; margin-top: 10px;
  font-family: var(--mono); font-size: 16px;
}}
.lg-confirmed {{ color: var(--confirmed); }}
.lg-probable  {{ color: var(--probable); }}
.lg-possible  {{ color: var(--possible); }}
.lg-unknown   {{ color: var(--unknown); }}

.detail-col {{
  padding: 24px; display: flex; flex-direction: column; gap: 22px;
}}

.meta-strip {{
  display: grid; grid-template-columns: repeat(4,1fr);
  gap: 1px; background: var(--border);
  border: 1px solid var(--border); border-radius: 3px; overflow: hidden;
}}
.meta-item {{ background: var(--bg); padding: 10px 14px; }}
.meta-key {{
  font-size: 12px; letter-spacing: 2px;
  color: var(--dim); text-transform: uppercase; margin-bottom: 4px;
}}
.meta-val {{ font-family: var(--mono); font-size: 16px; }}

.block-title {{
  font-size: 12px; font-weight: 600; letter-spacing: 2.5px;
  text-transform: uppercase; color: var(--dim);
  margin-bottom: 8px; padding-bottom: 4px;
  border-bottom: 1px solid var(--border);
}}
.tag-row {{ display: flex; flex-wrap: wrap; gap: 6px; }}

.dtable {{ width: 100%; border-collapse: collapse; font-size: 16px; }}
.dtable th {{
  font-size: 12px; letter-spacing: 1.5px; color: var(--dim);
  padding: 4px 10px; text-align: left;
  border-bottom: 1px solid var(--border);
}}
.dtable td {{
  padding: 6px 10px;
  border-bottom: 1px solid rgba(26,34,56,0.6);
  vertical-align: top;
}}
.dtable .row-label {{
  width: 120px; color: var(--dim); font-size: 16px;
}}

.card-footer {{
  display: grid; grid-template-columns: 1fr 1fr;
}}
.footer-col {{
  padding: 18px 24px;
  border-top: 1px solid var(--border);
}}
.footer-col + .footer-col {{
  border-left: 1px solid var(--border);
}}

/* ─── Tags & badges ───────────────────────────────────────────── */
.tag {{
  display: inline-block; font-family: var(--mono);
  font-size: 16px; padding: 2px 8px;
  border-radius: 2px; border: 1px solid;
}}
.tag-red    {{ background:rgba(255,68,85,.1);  color:var(--red);       border-color:var(--red); }}
.tag-green  {{ background:rgba(0,255,136,.08); color:var(--confirmed); border-color:var(--confirmed); }}
.tag-gray   {{ background:rgba(68,85,102,.15); color:var(--dim);       border-color:var(--unknown); }}
.tag-blue   {{ background:rgba(0,102,255,.1);  color:var(--blue);      border-color:#334488; }}
.tag-purple {{ background:rgba(130,80,255,.1); color:var(--purple);    border-color:#553388; }}
.badge {{
  display: inline-block; font-family: var(--mono);
  font-size: 16px; padding: 1px 6px;
  border-radius: 2px; border: 1px solid;
  letter-spacing: 0.5px;
}}

#details-area {{ margin-top: 0; }}
.details-toolbar {{
  display: none;
  align-items: center; justify-content: space-between;
  margin-bottom: 16px; padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}}
.details-toolbar.visible {{ display: flex; }}
.details-toolbar-label {{
  font-size: 16px; font-weight: 600;
  letter-spacing: 3px; text-transform: uppercase;
  color: var(--dim);
}}
.clear-all-btn {{
  font-family: var(--mono); font-size: 16px;
  letter-spacing: 1.5px; text-transform: uppercase;
  background: var(--bg3); color: var(--red);
  border: 1px solid var(--red);
  padding: 5px 12px; cursor: pointer;
  border-radius: 2px; transition: all 0.15s;
  opacity: 0.7;
}}
.clear-all-btn:hover {{ opacity: 1; }}

.mono   {{ font-family: var(--mono); }}
.muted  {{ color: var(--dim); }}
.center {{ text-align: center; }}
.wrap   {{ word-break: break-all; }}

.page-footer {{
  text-align: center; padding: 28px;
  color: var(--dim); font-family: var(--mono);
  font-size: 16px; letter-spacing: 1px;
  border-top: 1px solid var(--border); margin-top: 32px;
}}

@media (max-width: 960px) {{
  .card-body         {{ grid-template-columns: 1fr; }}
  .diamond-col       {{ border-right: none; border-bottom: 1px solid var(--border); }}
  .card-footer       {{ grid-template-columns: 1fr; }}
  .footer-col + .footer-col {{ border-left: none; }}
  .meta-strip        {{ grid-template-columns: repeat(2,1fr); }}
  .hdr-stats         {{ display: none; }}
  .page-header       {{ padding: 24px 24px; }}
  main               {{ padding: 24px 16px; }}
}}
</style>
</head>
<body>

<header class="page-header">
  <h1>Diamond Model — Intel Report</h1>
  <div class="subtitle">Generated {h(now)} &nbsp;·&nbsp; Schema v2.0</div>
  <div class="hdr-stats">
    <div class="stat">
      <div class="stat-n">{total}</div>
      <div class="stat-l">Events</div>
    </div>
    <div class="stat">
      <div class="stat-n red">{ongoing_count}</div>
      <div class="stat-l">Ongoing</div>
    </div>
  </div>
</header>

<main>

  <div class="section-label">Activity Thread — causal arc map</div>
  <div class="apt-filter-bar" id="apt-filter-bar">
    <span class="apt-filter-label">Filter by adversary:</span>
    {apt_filter_btns}
    <button class="apt-btn-all" onclick="selectAllApts()">All</button>
    <button class="apt-btn-all" onclick="selectNoneApts()">None</button>
  </div>
  <div class="thread-wrap" id="thread-wrap">
    {thread_svg}
  </div>

  <div class="section-header">
    <div class="section-label">Event Overview — click row to open detail</div>
    <button class="toggle-btn" id="toggle-resolved-btn" onclick="toggleResolved()">
      Show resolved events
    </button>
  </div>
  <table class="sum-table">
    <thead>
      <tr>
        <th>#</th><th>Incident ID</th><th>Detection</th><th>Status</th>
        <th>Adversary</th><th>Attack Type</th><th>Victim Assets</th><th>IoCs</th>
        <th>Links</th>
      </tr>
    </thead>
    <tbody>{summary_rows}</tbody>
  </table>

  <div id="details-area">
    <div class="details-toolbar" id="details-toolbar">
      <div class="details-toolbar-label">Event Details</div>
      <button class="clear-all-btn" onclick="clearAllDetails()">✕ Clear All</button>
    </div>
    {all_detail_panels}
  </div>

</main>

<div id="node-hover-popup" class="node-hover-popup" style="display:none">
  <div class="nhp-bracket nhp-tl"></div>
  <div class="nhp-bracket nhp-tr"></div>
  <div class="nhp-bracket nhp-bl"></div>
  <div class="nhp-bracket nhp-br"></div>
  <div class="nhp-header">
    <span class="nhp-num" id="nhp-num"></span>
    <span class="nhp-id"  id="nhp-id"></span>
    <span class="nhp-status" id="nhp-status"></span>
  </div>
  <div class="nhp-diamond" id="nhp-diamond"></div>
  <div class="nhp-click-hint">click to open detail ↓</div>
</div>

{hover_svgs}

<footer class="page-footer">
  DIAMOND MODEL &nbsp;·&nbsp; INTEL REPORT &nbsp;·&nbsp; {h(now)} &nbsp;·&nbsp; {total} EVENTS
</footer>

<script>
// ── Hover popup ──────────────────────────────────────────────────
var popup   = document.getElementById('node-hover-popup');
var popupDiamond = document.getElementById('nhp-diamond');
var popupNum     = document.getElementById('nhp-num');
var popupId      = document.getElementById('nhp-id');
var popupStatus  = document.getElementById('nhp-status');
var hoverTimer   = null;
var currentHit   = null;

var hits = document.querySelectorAll('.map-node-hit');

hits.forEach(function(hit) {{
  hit.addEventListener('mouseenter', function(e) {{
    currentHit = hit;
    clearTimeout(hoverTimer);
    showPopup(hit, e);
  }});
  hit.addEventListener('mousemove', function(e) {{
    positionPopup(e);
  }});
  hit.addEventListener('mouseleave', function() {{
    currentHit = null;
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(hidePopup, 80);
  }});
}});

popup.addEventListener('mouseenter', function() {{ clearTimeout(hoverTimer); }});
popup.addEventListener('mouseleave', function() {{
  hoverTimer = setTimeout(hidePopup, 80);
}});

function showPopup(hit, e) {{
  var idx  = parseInt(hit.getAttribute('data-idx'));
  var ong  = hit.getAttribute('data-ong') === '1';
  var incId = getIncidentId(idx);

  popupNum.textContent = '#' + String(idx + 1).padStart(2, '0');
  popupId.textContent  = incId;
  popupStatus.textContent = ong ? 'ONGOING' : 'RESOLVED';
  popupStatus.className   = 'nhp-status ' + (ong ? 'ong' : 'res');

  var src = document.getElementById('hover-svg-' + idx);
  popupDiamond.innerHTML = src ? src.innerHTML : '';

  popup.classList.toggle('ong', ong);

  positionPopup(e);
  popup.style.display = 'flex';
}}

function positionPopup(e) {{
  var pw = 440, ph = 380;
  var vw = window.innerWidth, vh = window.innerHeight;
  var cx = e.clientX, cy = e.clientY;
  var margin = 16;
  var x = cx + 14;
  if (x + pw > vw - margin) x = cx - pw - 14;
  var y = cy - ph / 2;
  if (y + ph > vh - margin) y = vh - margin - ph;
  if (y < margin) y = margin;
  popup.style.left = x + 'px';
  popup.style.top  = y + 'px';
}}

function hidePopup() {{
  popup.style.display = 'none';
  popupDiamond.innerHTML = '';
}}

function getIncidentId(idx) {{
  var panel = document.getElementById('detail-panel-' + idx);
  if (!panel) return 'Event ' + (idx + 1);
  var el = panel.querySelector('.ev-id');
  return el ? el.textContent.trim() : 'Event ' + (idx + 1);
}}

// ── Detail panel management ──────────────────────────────────────
var openPanels = new Set();

function openDetail(idx) {{
  var panel = document.getElementById('detail-panel-' + idx);
  if (!panel) return;
  hidePopup();
  if (panel.style.display !== 'none') {{
    panel.scrollIntoView({{behavior: 'smooth', block: 'start'}});
    return;
  }}
  panel.style.display = 'block';
  openPanels.add(idx);
  updateToolbar();
  setTimeout(function() {{
    panel.scrollIntoView({{behavior: 'smooth', block: 'start'}});
  }}, 50);
}}

function closeDetail(idx) {{
  var panel = document.getElementById('detail-panel-' + idx);
  if (panel) panel.style.display = 'none';
  openPanels.delete(idx);
  updateToolbar();
}}

function clearAllDetails() {{
  openPanels.forEach(function(idx) {{
    var panel = document.getElementById('detail-panel-' + idx);
    if (panel) panel.style.display = 'none';
  }});
  openPanels.clear();
  updateToolbar();
}}

function updateToolbar() {{
  var toolbar = document.getElementById('details-toolbar');
  if (openPanels.size > 0) {{
    toolbar.classList.add('visible');
  }} else {{
    toolbar.classList.remove('visible');
  }}
}}

// ── APT Filter & Resolved Filter ─────────────────────────────────
var aptActive = {{}};
var threadMeta = null;
var showingResolved = false;

function initAptFilter() {{
  var desc = document.getElementById('thread-meta');
  if (!desc) return;
  try {{
    threadMeta = JSON.parse(desc.textContent);
    threadMeta.forEach(function(t) {{
      aptActive[t.adv] = true;
    }});
  }} catch(e) {{ }}
  applyAptFilter();
}}

function toggleApt(btn) {{
  var adv = btn.getAttribute('data-adv');
  aptActive[adv] = !aptActive[adv];
  btn.classList.toggle('active', aptActive[adv]);
  applyAptFilter();
}}

function selectAllApts() {{
  Object.keys(aptActive).forEach(function(k) {{ aptActive[k] = true; }});
  document.querySelectorAll('.apt-btn').forEach(function(b) {{ b.classList.add('active'); }});
  applyAptFilter();
}}

function selectNoneApts() {{
  Object.keys(aptActive).forEach(function(k) {{ aptActive[k] = false; }});
  document.querySelectorAll('.apt-btn').forEach(function(b) {{ b.classList.remove('active'); }});
  applyAptFilter();
}}

function applyAptFilter() {{
  if (!threadMeta) return;

  var newColMap = {{}};
  var colIdx = 0;

  threadMeta.forEach(function(t, i) {{
    if (aptActive[t.adv] !== false) {{
      newColMap[t.col] = colIdx;
      colIdx++;
    }} else {{
      newColMap[t.col] = -1;
    }}
  }});

  var n_threads = colIdx;
  var LEFT_W = 380;
  var COL_W = 280;
  var ROW_H = 120;
  var TOP_H = 150;
  var NODE_R = 28;
  var SHRINK = NODE_R + 3;

  var content_w = LEFT_W + n_threads * COL_W + 50;
  var total_w = Math.max(1400, content_w);
  
  var svg = document.querySelector('.thread-svg');
  if(svg) {{
     var vb = svg.getAttribute('viewBox').split(' ');
     svg.setAttribute('viewBox', '0 0 ' + total_w + ' ' + vb[3]);
  }}

  document.querySelectorAll('.grid-row-bg').forEach(function(el) {{
     el.setAttribute('width', total_w);
  }});

  document.querySelectorAll('.apt-col-header').forEach(function(el) {{
    var origCol = parseInt(el.getAttribute('data-orig-col'));
    var nCol = newColMap[origCol];
    if (nCol === -1) {{
      el.style.display = 'none';
    }} else {{
      el.style.display = '';
      var cx = LEFT_W + nCol * COL_W + COL_W / 2;
      var bx = LEFT_W + nCol * COL_W;
      var rect = el.querySelector('rect');
      if(rect) rect.setAttribute('x', bx);
      el.querySelectorAll('text').forEach(function(t) {{
        t.setAttribute('x', cx);
      }});
    }}
  }});

  document.querySelectorAll('.apt-adv-band').forEach(function(el) {{
    var adv = el.getAttribute('data-adv');
    if (aptActive[adv] === false) {{
      el.style.display = 'none';
    }} else {{
      var origStart = parseInt(el.getAttribute('data-orig-start'));
      var origEnd = parseInt(el.getAttribute('data-orig-end'));
      
      var s = -1, e = -1;
      for (var c = origStart; c <= origEnd; c++) {{
        var nCol = newColMap[c];
        if (nCol !== -1) {{
          if (s === -1 || nCol < s) s = nCol;
          if (e === -1 || nCol > e) e = nCol;
        }}
      }}

      if (s === -1) {{
        el.style.display = 'none';
      }} else {{
        el.style.display = '';
        var x1 = LEFT_W + s * COL_W;
        var x2 = LEFT_W + (e + 1) * COL_W;
        var cx = (x1 + x2) / 2;
        var rect = el.querySelector('rect');
        var text = el.querySelector('text');
        if(rect) {{
            rect.setAttribute('x', x1);
            rect.setAttribute('width', x2 - x1);
        }}
        if(text) text.setAttribute('x', cx);
      }}
    }}
  }});

  document.querySelectorAll('.apt-node, .apt-hit').forEach(function(el) {{
    var origCol = parseInt(el.getAttribute('data-orig-col'));
    var nCol = newColMap[origCol];
    if (nCol === -1) {{
      el.style.display = 'none';
    }} else {{
      el.style.display = '';
      var cx = LEFT_W + nCol * COL_W + COL_W / 2;
      var oCx = LEFT_W + origCol * COL_W + COL_W / 2;
      var dx = cx - oCx;
      el.setAttribute('transform', 'translate(' + dx + ', 0)');
    }}
  }});

  document.querySelectorAll('.apt-el-edge').forEach(function(el) {{
    var srcOrigCol = parseInt(el.getAttribute('data-src-col'));
    var srcRow = parseInt(el.getAttribute('data-src-row'));
    var dstOrigCol = parseInt(el.getAttribute('data-dst-col'));
    var dstRow = parseInt(el.getAttribute('data-dst-row'));
    
    var srcNCol = newColMap[srcOrigCol];
    var dstNCol = newColMap[dstOrigCol];

    if (srcNCol === -1 || dstNCol === -1) {{
      el.style.display = 'none';
    }} else {{
      el.style.display = '';
      
      var x1 = LEFT_W + srcNCol * COL_W + COL_W / 2;
      var y1 = TOP_H + srcRow * ROW_H + ROW_H / 2;
      var x2 = LEFT_W + dstNCol * COL_W + COL_W / 2;
      var y2 = TOP_H + dstRow * ROW_H + ROW_H / 2;

      var dx = x2 - x1, dy = y2 - y1;
      var dist = Math.hypot(dx, dy);
      if (dist < 1) {{
         el.style.display = 'none'; 
         return;
      }}
      var ux = dx / dist, uy = dy / dist;
      var sx = x1 + ux * SHRINK, sy = y1 + uy * SHRINK;
      var ex = x2 - ux * SHRINK, ey = y2 - uy * SHRINK;

      var same_col = Math.abs(x1 - x2) < 5;
      var shape = el.querySelector('.edge-path');
      if (shape) {{
        if (same_col) {{
          var mx = (sx + ex) / 2, my = (sy + ey) / 2;
          shape.setAttribute('d', 'M ' + sx.toFixed(1) + ',' + sy.toFixed(1) + ' Q ' + mx.toFixed(1) + ',' + my.toFixed(1) + ' ' + ex.toFixed(1) + ',' + ey.toFixed(1));
        }} else {{
          var mx = (sx + ex) / 2, my = (sy + ey) / 2;
          var perp_x = -uy, perp_y = ux;
          var bend = Math.min(55, dist * 0.25);
          var cpx = mx + perp_x * bend;
          var cpy = my + perp_y * bend;
          shape.setAttribute('d', 'M ' + sx.toFixed(1) + ',' + sy.toFixed(1) + ' Q ' + cpx.toFixed(1) + ',' + cpy.toFixed(1) + ' ' + ex.toFixed(1) + ',' + ey.toFixed(1));
        }}
      }}
    }}
  }});

  document.querySelectorAll('.sum-table tbody tr').forEach(function(row) {{
    var adv = row.getAttribute('data-adv');
    if (!adv) return;
    var showApt = aptActive[adv] !== false;
    var isRes = row.classList.contains('row-resolved');
    if (!showApt || (isRes && !showingResolved)) {{
      row.style.display = 'none';
    }} else {{
      row.style.display = '';
    }}
  }});
}}
function toggleResolved() {{
  showingResolved = !showingResolved;
  var btn = document.getElementById('toggle-resolved-btn');
  btn.textContent = showingResolved ? 'Hide resolved events' : 'Show resolved events';
  btn.classList.toggle('active', showingResolved);
  applyAptFilter();
}}

document.querySelectorAll('.sum-table tbody tr').forEach(function(row) {{
  var cells = row.querySelectorAll('td');
  if (cells.length >= 5) {{
    row.setAttribute('data-adv', cells[4].textContent.trim());
  }}
}});

initAptFilter();
</script>

</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python diamond_report.py <json_dir>[output.html]")
        sys.exit(1)

    json_dir    = Path(sys.argv[1])
    output_html = Path(sys.argv[2]) if len(sys.argv) > 2 else json_dir / "diamond_report.html"

    if not json_dir.is_dir():
        print(f"Error: not a directory: {json_dir}")
        sys.exit(1)

    events = load_events(json_dir)
    if not events:
        print("No JSON files found in directory.")
        sys.exit(0)

    # 1. CLI summary table
    print_cli_table(events)

    # 2. HTML report
    html_content = generate_html(events)
    output_html.write_text(html_content, encoding="utf-8")
    print(f"✓  HTML report → {output_html}")


if __name__ == "__main__":
    main()