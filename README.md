#!/usr/bin/env python3
"""
Panorama-only read-only workflow (single-config-pull, multi-IP, fast)
- Logs into Panorama once (Netmiko CLI, set-output to 'set' format)
- Pulls the entire running config in set format ONCE
- For each IP in IPS_TO_CHECK:
    • Finds address objects (shared + DG) that map to the IP
    • Finds any address-groups that include those objects (static groups)
    • Finds security rules that reference the IP/object/group
    • Finds NAT rules that reference the IP/object/group (original/translated fields)
- Writes a stitched text report to ./logs/results_YYYYmmdd_HHMMSS.txt

NOTE: CLI text scraping (no API key). Matches literal strings; CIDRs/ranges that *include* an IP
but don’t spell it out will be missed.
"""

import os, re, logging, datetime as dt
from typing import List, Dict, Set, Tuple
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS =========
USERNAME = ""
PASSWORD = ""

PANORAMA_HOST = "10.21.128.226"

IPS_TO_CHECK = [
    "10.224.160.85",
    # add more IPs here
]

MAX_READ_TIMEOUT = 600   # large to allow full config pull
LOG_DIR = "./logs-3"
ENABLE_NETMIKO_DEBUG = True
os.makedirs(LOG_DIR, exist_ok=True)

if ENABLE_NETMIKO_DEBUG:
    logging.basicConfig(
        filename=os.path.join(LOG_DIR, "netmiko_debug.log"),
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("netmiko").setLevel(logging.DEBUG)

# ---------- helpers ----------

def _session_log_path(host: str, kind: str) -> str:
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return os.path.join(LOG_DIR, f"{kind}_{host.replace(':','_')}_{ts}.session.log")

def _write_log(fname: str, text: str):
    try:
        with open(os.path.join(LOG_DIR, fname), "w", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass

# ---------- Panorama connect ----------

def connect_panorama(host: str, title: str = "Panorama"):
    info = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": USERNAME,
        "password": PASSWORD,
        "fast_cli": True,              # faster IO
        "global_delay_factor": 1.0,
        "session_log": _session_log_path(host, "panorama"),
    }
    try:
        conn = ConnectHandler(**info)
        # ensure set-format + comfy terminal
        conn.send_command("set cli config-output-format set", expect_string=r">|#")
        conn.send_command("set cli pager off", expect_string=r">|#")
        conn.send_command("set cli terminal width 500", expect_string=r">|#")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise RuntimeError(f"Failed to connect to {title or host}: {e}")

def pull_full_set_config(conn) -> List[str]:
    """Enter config mode and run a single 'show' to get the full set-format config."""
    conn.config_mode()
    # 'show' in config mode prints the candidate config in the currently-selected format ('set')
    full = conn.send_command("show", expect_string=r"#", read_timeout=MAX_READ_TIMEOUT)
    conn.exit_config_mode()
    _write_log("panorama_full_set_config.txt", full)
    # Keep only meaningful lines
    lines = [ln.strip() for ln in full.splitlines() if ln.strip().startswith("set ")]
    return lines

# ---------- Parsers / Index builders ----------

ADDR_RE_SHARED = re.compile(r"^set\s+shared\s+address\s+(\S+)\s+ip-netmask\s+(\S+)\s*$")
ADDR_RE_DG     = re.compile(r"^set\s+device-group\s+(\S+)\s+address\s+(\S+)\s+ip-netmask\s+(\S+)\s*$")

# Static groups:
#   set shared address-group G static [ obj1 obj2 ... ]
#   set device-group DG address-group G static [ obj1 obj2 ... ]
#   (Sometimes vendors emit multiple lines; we handle both bracketed and unbracketed)
GRP_RE_SHARED  = re.compile(r"^set\s+shared\s+address-group\s+(\S+)\s+static\s+(.*)$")
GRP_RE_DG      = re.compile(r"^set\s+device-group\s+(\S+)\s+address-group\s+(\S+)\s+static\s+(.*)$")

# Security rules and NAT rules live under:
#   set device-group <DG> (pre-rulebase|post-rulebase) security rules <RULE> ...
#   set device-group <DG> (pre-rulebase|post-rulebase) nat rules <RULE> ...
SEC_HDR_RE     = re.compile(r"^set\s+device-group\s+(\S+)\s+(pre-rulebase|post-rulebase)\s+security\s+rules\s+(\S+)\s+(.*)$")
NAT_HDR_RE     = re.compile(r"^set\s+device-group\s+(\S+)\s+(pre-rulebase|post-rulebase)\s+nat\s+rules\s+(\S+)\s+(.*)$")

def tokenize_static_members(raw: str) -> List[str]:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1].strip()
    # split on whitespace; PA names cannot contain spaces
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

    # Keep rule lines for a later token filter (we don't know tokens yet)
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
            dg, where, rule, rest = m.group(1), m.group(2), m.group(3), m.group(4)
            sec_lines.append((dg, where, rule, s))
            continue

        m = NAT_HDR_RE.match(s)
        if m:
            dg, where, rule, rest = m.group(1), m.group(2), m.group(3), m.group(4)
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
    # Pre-compile token regexes once
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

    print("\n=== Panorama IP Audit (addresses, NAT, security) — single-config-pull ===")
    print(f"Panorama: {PANORAMA_HOST}")
    print(f"IPs: {', '.join(IPS_TO_CHECK)}")
    print(f"Logs dir: {os.path.abspath(LOG_DIR)}\n")

    pano = connect_panorama(PANORAMA_HOST)

    # One config pull
    set_lines = pull_full_set_config(pano)
    pano.disconnect()

    # Build indexes from the one pull
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
