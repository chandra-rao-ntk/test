#!/usr/bin/env python3
"""
Panorama-only read-only workflow (single-config-pull, multi-IP, fast)
- Reads the entire running config (set format) from a local file (config.txt)
- For each IP in IPS_TO_CHECK:
    • Finds address objects (shared + DG) that map to the IP
    • Finds any address-groups that include those objects (static groups)
    • Finds security rules that reference the IP/object/group
    • Finds NAT rules that reference the IP/object/group (original/translated fields)
- Writes a stitched text report to ./logs-3/results_YYYYmmdd_HHMMSS.txt

NOTE: Text scraping. Matches literal strings; CIDRs/ranges that *include* an IP
but don’t spell it out will be missed.
"""

import os, re, logging, datetime as dt
from typing import List, Dict, Set, Tuple

# ========= USER SETTINGS =========
CONFIG_PATH = "./configs"   # EITHER a directory containing 'config.txt' OR a full file path
CONFIG_FILENAME = "config.txt"

IPS_TO_CHECK = [
    "10.224.160.85",
    # add more IPs here
]

LOG_DIR = "./logs-3"
MAX_READ_TIMEOUT = 600  # kept for parity; unused with file
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "parser_debug.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# ---------- helpers ----------

def _resolve_config_path(path_or_dir: str, fname: str) -> str:
    """Return a real file path. If given a directory, append fname."""
    if os.path.isdir(path_or_dir):
        return os.path.join(path_or_dir, fname)
    return path_or_dir  # assume it's a file

def _write_log(fname: str, text: str):
    try:
        with open(os.path.join(LOG_DIR, fname), "w", encoding="utf-8") as f:
            f.write(text)
    except Exception as e:
        logging.warning(f"Failed to write log {fname}: {e}")

# ---------- Config loading (LOCAL FILE) ----------

def pull_full_set_config_from_file(path_or_dir: str, fname: str = "config.txt") -> List[str]:
    """
    Read a local config and return only meaningful 'set ' lines.
    The file may contain mixed output; we keep lines that start with 'set '.
    """
    path = _resolve_config_path(path_or_dir, fname)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    _write_log("panorama_full_set_config.txt", raw)

    # Keep only lines that look like 'set ...'
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("set ")]
    return lines

# ---------- Parsers / Index builders ----------

ADDR_RE_SHARED = re.compile(r"^set\s+shared\s+address\s+(\S+)\s+ip-netmask\s+(\S+)\s*$")
ADDR_RE_DG     = re.compile(r"^set\s+device-group\s+(\S+)\s+address\s+(\S+)\s+ip-netmask\s+(\S+)\s*$")

# Static groups:
#   set shared address-group G static [ obj1 obj2 ... ]
#   set device-group DG address-group G static [ obj1 obj2 ... ]
GRP_RE_SHARED  = re.compile(r"^set\s+shared\s+address-group\s+(\S+)\s+static\s+(.*)$")
GRP_RE_DG      = re.compile(r"^set\s+device-group\s+(\S+)\s+address-group\s+(\S+)\s+static\s+(.*)$")

# Security / NAT rules
SEC_HDR_RE     = re.compile(r"^set\s+device-group\s+(\S+)\s+(pre-rulebase|post-rulebase)\s+security\s+rules\s+(\S+)\s+(.*)$")
NAT_HDR_RE     = re.compile(r"^set\s+device-group\s+(\S+)\s+(pre-rulebase|post-rulebase)\s+nat\s+rules\s+(\S+)\s+(.*)$")

def tokenize_static_members(raw: str) -> List[str]:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1].strip()
    return [t for t in raw.split() if t and t not in {"[", "]"}]

def build_indexes(lines: List[str]):
    """
    Build fast reverse indexes from a single pass of set-lines:
      - ip_index: ip_literal -> list({name, scope})
      - group_index: object_name -> list({name, scope})
      - sec_lines: raw lines (for later token scan)
      - nat_lines: raw lines (for later token scan)
    """
    ip_index: Dict[str, List[Dict[str, str]]] = {}
    group_index: Dict[str, List[Dict[str, str]]] = {}

    sec_lines: List[Tuple[str, str, str, str]] = []  # (dg, where, rule, full_line)
    nat_lines: List[Tuple[str, str, str, str]] = []

    for s in lines:
        m = ADDR_RE_SHARED.match(s)
        if m:
            name, ipmask = m.group(1), m.group(2)
            ip_literal = ipmask.split("/")[0]
            ip_index.setdefault(ip_literal, []).append({"name": name, "scope": "shared"})
            continue

        m = ADDR_RE_DG.match(s)
        if m:
            dg, name, ipmask = m.group(1), m.group(2), m.group(3)
            ip_literal = ipmask.split("/")[0]
            ip_index.setdefault(ip_literal, []).append({"name": name, "scope": f"device-group {dg}"})
            continue

        m = GRP_RE_SHARED.match(s)
        if m:
            gname, tail = m.group(1), m.group(2)
            members = tokenize_static_members(tail)
            for obj in members:
                group_index.setdefault(obj, []).append({"name": gname, "scope": "shared"})
            continue

        m = GRP_RE_DG.match(s)
        if m:
            dg, gname, tail = m.group(1), m.group(2), m.group(3)
            members = tokenize_static_members(tail)
            for obj in members:
                group_index.setdefault(obj, []).append({"name": gname, "scope": f"device-group {dg}"})
            continue

        m = SEC_HDR_RE.match(s)
        if m:
            dg, where, rule, _ = m.group(1), m.group(2), m.group(3), m.group(4)
            sec_lines.append((dg, where, rule, s))
            continue

        m = NAT_HDR_RE.match(s)
        if m:
            dg, where, rule, _ = m.group(1), m.group(2), m.group(3), m.group(4)
            nat_lines.append((dg, where, rule, s))
            continue

    return ip_index, group_index, sec_lines, nat_lines

# ---------- classifiers & formatters ----------

def _classify_sec_field(set_line: str) -> str:
    t = f" {set_line} "
    if " source " in t: return "source"
    if " destination " in t: return "destination"
    if " from " in t: return "from-zone"
    if " to " in t: return "to-zone"
    if " service " in t: return "service"
    return "unknown"

def _classify_nat_field(set_line: str) -> str:
    t = f" {set_line} "
    if " original-packet source " in t: return "original-source"
    if " original-packet destination " in t: return "original-destination"
    if " destination-translation translated-address " in t or " destination-translation dynamic-dns " in t:
        return "dst-translation"
    if (" source-translation static-ip " in t or
        " source-translation translated-address " in t or
        " source-translation dynamic-ip-and-port " in t):
        return "src-translation"
    if " to-interface " in t: return "to-interface"
    if " service " in t: return "service"
    return "unknown"

def _lines_section_header(ip: str):
    return [f"===== IP: {ip} ====="]

def _lines_addr_objs(objs):
    if objs:
        lines = ["Address object(s):"]
        for o in objs:
            lines.append(f"  - {o['name']} ({o['scope']})")
        return lines
    return ["Address object(s): <none found>"]

def _lines_groups(groups):
    if groups:
        lines = ["Address-group(s) containing the object(s):"]
        for g in groups:
            lines.append(f"  - {g['name']} ({g['scope']})")
        return lines
    return ["Address-group(s) containing the object(s): <none>"]

def _collapse_rule_refs(refs):
    agg = {}
    for r in refs:
        key = (r["dg"], r["where"], r["rule"])
        if key not in agg:
            agg[key] = {"fields": set(), "tokens": set()}
        agg[key]["fields"].add(r["field"])
        agg[key]["tokens"].add(r["token"])
    out = []
    for (dg, where, rule), v in sorted(agg.items()):
        fields = ",".join(sorted(v["fields"]))
        toks = ",".join(sorted(v["tokens"]))
        out.append(f"  - DG={dg:<14} {where:<12} rule={rule:<40} fields=[{fields}] via=[{toks}]")
    return out

def _lines_security(refs):
    if refs:
        return ["Security rules referencing the IP/object/group:"] + _collapse_rule_refs(refs)
    return ["Security rules referencing the IP/object/group: <none>"]

def _lines_nat(refs):
    if refs:
        return ["NAT rules referencing the IP/object/group:"] + _collapse_rule_refs(refs)
    return ["NAT rules referencing the IP/object/group: <none>"]

# ---------- lookups on the single pulled config ----------

def find_addr_objs_for_ip(ip_index, ip: str):
    return list({(o["name"], o["scope"]): o for o in ip_index.get(ip, [])}.values())

def find_groups_for_objects(group_index, objs: List[Dict[str,str]]):
    seen = set()
    out = []
    for o in objs:
        for g in group_index.get(o["name"], []):
            key = (g["name"], g["scope"])
            if key not in seen:
                seen.add(key)
                out.append(g)
    return out

def _token_regex(token: str) -> re.Pattern:
    # strict token match (avoid substrings)
    return re.compile(rf"(?<!\S){re.escape(token)}(?!\S)")

def scan_rules_for_tokens(lines_with_meta: List[Tuple[str,str,str,str]], tokens: Set[str], is_nat=False):
    refs = []
    token_regexes = [(tok, _token_regex(tok)) for tok in sorted(tokens)]
    for (dg, where, rule, full_line) in lines_with_meta:
        for tok, rx in token_regexes:
            if rx.search(full_line):
                field = _classify_nat_field(full_line) if is_nat else _classify_sec_field(full_line)
                refs.append({"token": tok, "dg": dg, "where": where, "rule": rule, "field": field})
    return refs

# ---------- main ----------

def main():
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = os.path.join(LOG_DIR, f"results_{ts}.txt")

    resolved_cfg_path = _resolve_config_path(CONFIG_PATH, CONFIG_FILENAME)
    print("\n=== Panorama IP Audit (addresses, NAT, security) — single-config-file ===")
    print(f"Config file: {os.path.abspath(resolved_cfg_path)}")
    print(f"IPs: {', '.join(IPS_TO_CHECK)}")
    print(f"Logs dir: {os.path.abspath(LOG_DIR)}\n")

    # One config read from local file
    set_lines = pull_full_set_config_from_file(CONFIG_PATH, CONFIG_FILENAME)

    # Build indexes from the one read
    ip_index, group_index, sec_lines, nat_lines = build_indexes(set_lines)

    out_lines = []

    # Precompute everything per-IP based on the single cached config
    for ip in IPS_TO_CHECK:
        out_lines += _lines_section_header(ip)

        # 1) Address objects that literally specify this IP
        objs = find_addr_objs_for_ip(ip_index, ip)
        out_lines += _lines_addr_objs(objs)

        # 2) Static groups containing those objects
        groups = find_groups_for_objects(group_index, objs)
        out_lines += _lines_groups(groups)

        # Tokens: IP itself + object names + group names
        tokens: Set[str] = {ip}
        tokens.update([o["name"] for o in objs])
        tokens.update([g["name"] for g in groups])

        # 3) Security rule refs
        sec_refs = scan_rules_for_tokens(sec_lines, tokens, is_nat=False)
        out_lines += _lines_security(sec_refs)

        # 4) NAT rule refs
        nat_refs = scan_rules_for_tokens(nat_lines, tokens, is_nat=True)
        out_lines += _lines_nat(nat_refs)

        out_lines.append("")

    with open(results_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    print("\n".join(out_lines))
    print(f"\nSaved stitched report: {os.path.abspath(LOG_DIR)}/{os.path.basename(results_path)}")

if __name__ == "__main__":
    main()
