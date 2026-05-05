#!/usr/bin/env python3
"""
md_to_diamond.py
Parses an incident report Markdown file and outputs a Diamond Model JSON instance.

Usage:
    python md_to_diamond.py <input.md> <event_name> [output_dir]

Arguments:
    input.md      Path to the filled-in incident report Markdown file.
    event_name    Short name for the event (e.g. "phishing_hr_dept").
                  Spaces are replaced with underscores automatically.
    output_dir    Optional. Directory to write the JSON file into.
                  Defaults to the same directory as the input file.

Output filename format:
    YYYY-MM-DD--HH-MM_<event_name>.json

Timestamp priority for filename (first available wins):
    1. detection time   — almost always known; triggers the report
    2. attack_start     — often reconstructed later or unknown
    3. last_updated     — always present as a last resort

Related Events section (optional, section 12):
    Each bullet names another event file (without .json extension) and
    an optional confidence value (0.0–1.0).

    Examples:
        - 2026-05-02--07-15_ubuntu_ddos
        - 2026-05-03--09-00_lateral_move | 0.6
        - 2026-05-04--11-30_exfil_attempt | confidence: 0.85

    Confidence rendering in the activity-thread table:
        1.0        → solid line      (confirmed causal link)
        0.5–0.99   → dashed line     (probable)
        < 0.5      → dotted line     (hypothesised)
"""

import re
import json
import sys
from pathlib import Path
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Timestamp handling
# ---------------------------------------------------------------------------

# Expected format filled in by operators: "YYYY-MM-DD HH:MM"
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M"

# Alternative: if operators use ISO 8601 instead, swap to this:
# TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"  # strict ISO
# TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M"     # ISO without seconds


def parse_timestamp(raw: str | None) -> datetime | None:
    """
    Parse a timestamp string into a datetime object.
    Returns None if raw is empty or doesn't match the expected format.
    """
    if not raw:
        return None
    try:
        return datetime.strptime(raw.strip(), TIMESTAMP_FORMAT)
    except ValueError:
        return None


def dt_to_str(dt: datetime | None) -> str | None:
    """Serialize a datetime back to the operator format, or None."""
    if dt is None:
        return None
    return dt.strftime(TIMESTAMP_FORMAT)


def build_output_filename(
    event_name: str,
    detection_time: str | None,
    attack_start: str | None,
    last_updated: str | None,
) -> str:
    """
    Build the output filename using the format YYYY-MM-DD--HH-MM_<event_name>.json.

    Timestamp priority (first parseable wins):
      1. detection_time  — almost always known; triggers the report
      2. attack_start    — often unknown or reconstructed later
      3. last_updated    — last resort, always present
    """
    slug = re.sub(r"\s+", "_", event_name.strip()).lower()

    for candidate in (detection_time, attack_start, last_updated):
        dt = parse_timestamp(candidate)
        if dt:
            prefix = dt.strftime("%Y-%m-%d--%H-%M")
            return f"{prefix}_{slug}.json"

    # Absolute fallback: use current time (should never happen in practice)
    prefix = datetime.now().strftime("%Y-%m-%d--%H-%M")
    return f"{prefix}_{slug}.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def clean(text: str) -> str | None:
    """Strip whitespace; return None if the result is empty."""
    t = text.strip()
    return t if t else None


def checked_boxes(block: str) -> list[str]:
    """
    Return the labels of all checked checkboxes ([x] or [X]) in a block.
    Also captures the free-text value after 'Other:' if that line is checked.
    """
    results = []
    for line in block.splitlines():
        m = re.match(r"\s*-\s*\[([xX])\]\s*(.*)", line)
        if m:
            label = m.group(2).strip()
            # Handle  "Other: some text"
            other_m = re.match(r"Other:\s*(.*)", label, re.IGNORECASE)
            if other_m:
                other_val = other_m.group(1).strip()
                results.append(f"Other: {other_val}" if other_val else "Other")
            else:
                results.append(label)
    return results


def section_body(md: str, header_pattern: str) -> str:
    """
    Extract the text body of a section identified by a regex pattern
    matching its heading line.  Stops at the next ## / ### heading.
    """
    m = re.search(header_pattern, md, re.IGNORECASE | re.MULTILINE)
    if not m:
        return ""
    start = m.end()
    # Find the next heading at the same or higher level
    next_heading = re.search(r"^#{1,3}\s", md[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(md)
    return md[start:end]


def bullet_value(block: str, key: str) -> str | None:
    """
    Extract the value from a bullet like '- Key: value'.
    Returns None if not found or value is empty.
    """
    m = re.search(rf"-\s*{re.escape(key)}[:\s]+(.+)", block, re.IGNORECASE)
    return clean(m.group(1)) if m else None


def free_text_lines(block: str) -> list[str]:
    """
    Collect non-empty, non-heading, non-checkbox bullet content from a block.
    Skips lines that are just '- ' with nothing after them.
    """
    lines = []
    for line in block.splitlines():
        line = line.strip()
        # Skip empty, headings, checkbox lines, and bare dashes
        if not line or line.startswith("#"):
            continue
        if re.match(r"-\s*\[[ xX]\]", line):
            continue
        m = re.match(r"-\s+(.*)", line)
        if m:
            val = m.group(1).strip()
            if val:
                lines.append(val)
    return lines


def ioc_entries(block: str) -> list[dict]:
    """
    Parse IoC bullet lines.  Tries to detect the type automatically.
    Expected format (loose):  '- <type>: <value>'  or just  '- <value>'
    """
    known_types = {
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        "hash_md5": r"\b[0-9a-fA-F]{32}\b",
        "hash_sha1": r"\b[0-9a-fA-F]{40}\b",
        "hash_sha256": r"\b[0-9a-fA-F]{64}\b",
        "email": r"\b[^@\s]+@[^@\s]+\.[^@\s]+\b",
        "url": r"https?://\S+",
        "filepath": r"(?:[A-Za-z]:\\|/)[^\s]+",
    }

    entries = []
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"-\s+(.*)", line)
        if not m:
            continue
        raw = m.group(1).strip()
        if not raw:
            continue

        # Try explicit 'type: value' format first
        explicit = re.match(r"([a-zA-Z0-9_\- ]+):\s+(.+)", raw)
        if explicit:
            ioc_type = explicit.group(1).strip().lower().replace(" ", "_")
            value = explicit.group(2).strip()
        else:
            value = raw
            # Auto-detect type
            ioc_type = "unknown"
            for t, pattern in known_types.items():
                if re.search(pattern, value):
                    ioc_type = t
                    break

        entries.append({
            "type": ioc_type,
            "value": value,
            "confidence": "unknown"
        })
    return entries


def parse_ongoing(block: str) -> bool | None:
    """Map the checked ongoing-status checkbox to True / False / None."""
    boxes = checked_boxes(block)
    if not boxes:
        return None
    label = boxes[0].lower()
    if "yes" in label:
        return True
    if "no" in label:
        return False
    return None   # "Unknown" or anything else


def parse_assets(block: str) -> list[dict]:
    """
    Parse one or more Asset / Owner pairs.
    Supports repeated  '- Asset: ...'  /  '- Owner: ...'  groups.
    """
    assets = []
    asset_matches = list(re.finditer(r"-\s*Asset[:\s]+(.*)", block, re.IGNORECASE))
    owner_matches = list(re.finditer(r"-\s*Owner[:\s]+(.*)", block, re.IGNORECASE))

    for i, am in enumerate(asset_matches):
        asset_val = clean(am.group(1))
        owner_val = clean(owner_matches[i].group(1)) if i < len(owner_matches) else None
        if asset_val or owner_val:
            assets.append({
                "asset": asset_val or "",
                "owner": owner_val or "",
                "confidence": "unknown"
            })
    return assets or [{"asset": "", "owner": "", "confidence": "unknown"}]


def parse_personnel(block: str) -> list[dict]:
    """Parse one or more Name / Role pairs."""
    personnel = []
    name_matches = list(re.finditer(r"-\s*Name[:\s]+(.*)", block, re.IGNORECASE))
    role_matches = list(re.finditer(r"-\s*Role[:\s]+(.*)", block, re.IGNORECASE))

    for i, nm in enumerate(name_matches):
        name_val = clean(nm.group(1))
        role_val = clean(role_matches[i].group(1)) if i < len(role_matches) else None
        if name_val or role_val:
            personnel.append({
                "name": name_val or "",
                "role": role_val or ""
            })
    return personnel or [{"name": "", "role": ""}]


def parse_related_events(block: str) -> list[dict]:
    """
    Parse the Related Events section (section 12).

    Each non-empty bullet names another event file (stem without .json)
    and an optional numeric confidence (0.0–1.0).  Defaults to 1.0.

    Accepted formats (all equivalent):
        - 2026-05-02--07-15_ubuntu_ddos
        - 2026-05-02--07-15_ubuntu_ddos | 0.6
        - 2026-05-02--07-15_ubuntu_ddos | confidence: 0.85

    Confidence interpretation (used by the activity-thread renderer):
        1.0        → solid line   (confirmed causal link)
        0.5–0.99   → dashed line  (probable)
        < 0.5      → dotted line  (hypothesised)
    """
    entries = []
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"-\s+(.*)", line)
        if not m:
            continue
        raw = m.group(1).strip()
        if not raw:
            continue

        # Split on pipe to get optional confidence annotation
        if "|" in raw:
            name_part, conf_part = raw.split("|", 1)
            name_part = name_part.strip()
            conf_part = conf_part.strip()
            # Strip "confidence:" prefix if present
            conf_part = re.sub(r"(?i)^confidence\s*:\s*", "", conf_part).strip()
            try:
                conf_val = float(conf_part)
                conf_val = max(0.0, min(1.0, conf_val))  # clamp to [0, 1]
            except ValueError:
                conf_val = 1.0
        else:
            name_part = raw.strip()
            conf_val = 1.0

        # Strip .json extension if operators accidentally include it
        name_part = re.sub(r"\.json$", "", name_part, flags=re.IGNORECASE).strip()

        if name_part:
            entries.append({
                "id_or_name": name_part,
                "confidence": conf_val
            })
    return entries


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_md(md: str) -> dict:
    now_iso = datetime.now(timezone.utc).isoformat()

    # --- Incident header (before first ##) ----------------------------------
    header = md.split("##")[0]
    incident_id   = bullet_value(header, "Incident Nr")
    last_updated  = bullet_value(header, "Last Updated")

    # --- Individual sections ------------------------------------------------
    s_detection  = section_body(md, r"^#{1,3}\s+1\.\s+Time of Detection")
    s_attack     = section_body(md, r"^#{1,3}\s+2\.\s+Time of Attack")
    s_ongoing    = section_body(md, r"^#{1,3}\s+3\.\s+Is the attack")
    s_assets     = section_body(md, r"^#{1,3}\s+4\.\s+Affected Asset")
    s_personnel  = section_body(md, r"^#{1,3}\s+5\.\s+Assigned Personnel")
    s_conf       = section_body(md, r"^#{1,3}\s+6\.\s+Impact on Confidentiality")
    s_integ      = section_body(md, r"^#{1,3}\s+7\.\s+Impact on Integrity")
    s_avail      = section_body(md, r"^#{1,3}\s+8\.\s+Impact on Availability")
    s_atk_type   = section_body(md, r"^#{1,3}\s+9\.\s+Attack Type")
    s_atk_vec    = section_body(md, r"^#{1,3}\s+10\.\s+Attack Vector")
    s_iocs       = section_body(md, r"^#{1,3}\s+11\.\s+Indicators of Compromise")
    s_related    = section_body(md, r"^#{1,3}\s+12\.\s+Related Events")

    # Free-text values
    detection_time = clean("\n".join(free_text_lines(s_detection)))
    attack_time    = clean("\n".join(free_text_lines(s_attack)))

    conf_desc  = clean("\n".join(free_text_lines(s_conf)))
    integ_desc = clean("\n".join(free_text_lines(s_integ)))
    avail_desc = clean("\n".join(free_text_lines(s_avail)))

    attack_types   = checked_boxes(s_atk_type)
    attack_vectors = checked_boxes(s_atk_vec)
    iocs           = ioc_entries(s_iocs)
    related_events = parse_related_events(s_related)

    # --- Assemble JSON ------------------------------------------------------
    return {
        "schema_version": "2.0",

        "incident": {
            "id":           incident_id or "",
            "last_updated": last_updated or now_iso,
            "confidence":   "confirmed"
        },

        "meta_features": {
            "timestamp": {
                "attack_start": attack_time or "",
                "attack_end":   None,
                "detection":    detection_time or "",
                "confidence":   "unknown" if not attack_time else "probable"
            },

            "phase": {
                "kill_chain_phase": None,
                "confidence":       "unknown"
            },

            "result": {
                "outcome": None,
                "cia_impact": {
                    "confidentiality": {
                        "description": conf_desc or "",
                        "confidence":  "unknown" if not conf_desc else "probable"
                    },
                    "integrity": {
                        "description": integ_desc or "",
                        "confidence":  "unknown" if not integ_desc else "probable"
                    },
                    "availability": {
                        "description": avail_desc or "",
                        "confidence":  "unknown" if not avail_desc else "probable"
                    }
                },
                "confidence": "unknown"
            },

            "direction": {
                "value":      None,
                "confidence": "unknown"
            },

            "methodology": {
                "attack_type":   attack_types,
                "attack_vector": attack_vectors,
                "confidence":    "unknown" if not attack_types else "probable"
            },

            "resources": {
                "software":  [],
                "hardware":  [],
                "funds":     None,
                "knowledge": [],
                "confidence": "unknown"
            },

            "related_events": related_events
        },

        "diamond_model": {

            "adversary": {
                "name":       None,
                "aliases":    [],
                "motivation": None,
                "intent":     None,
                "confidence": "unknown"
            },

            "capability": {
                "description": None,
                "iocs":        iocs if iocs else [],
                "confidence":  "unknown" if not iocs else "probable"
            },

            "infrastructure": {
                "tier": None,
                "ip_addresses": [],
                "domains":      [],
                "tools_used":   [],
                "notes":        None,
                "confidence":   "unknown"
            },

            "victim": {
                "assets":     parse_assets(s_assets),
                "confidence": "confirmed" if s_assets.strip() else "unknown"
            },

            "extended": {
                "socio_political": {
                    "description":      None,
                    "adversary_intent": None,
                    "victim_exposure":  None,
                    "confidence":       "unknown"
                },
                "technology": {
                    "description":                        None,
                    "capability_infrastructure_relation": None,
                    "confidence":                         "unknown"
                }
            }

        },

        "response": {
            "ongoing":            parse_ongoing(s_ongoing),
            "assigned_personnel": parse_personnel(s_personnel)
        }
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage: python md_to_diamond.py <input.md> <event_name> [output_dir]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    event_name = sys.argv[2]
    output_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else input_path.parent

    if not input_path.exists():
        print(f"Error: file not found: {input_path}")
        sys.exit(1)

    md_text = input_path.read_text(encoding="utf-8")
    result  = parse_md(md_text)

    # Build the filename from parsed timestamps + event name
    ts      = result["meta_features"]["timestamp"]
    header  = result["incident"]
    filename = build_output_filename(
        event_name     = event_name,
        detection_time = ts["detection"],
        attack_start   = ts["attack_start"],
        last_updated   = header["last_updated"],
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"✓  Written to {output_path}")


if __name__ == "__main__":
    main()
