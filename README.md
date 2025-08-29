#!/usr/bin/env python3
"""
Panorama-only IP Audit — FAST VERSION

Key speedups vs. prior script:
1) **One config pull**: Download the entire running config in `set` format once, then do all lookups locally in Python (no per-IP/per-token CLI calls).
2) **In-memory indexes**: Build reverse lookups for address objects, address-groups, and rule lines so queries are O(1)/O(log n) instead of O(n) CLI scans.
3) **Optional parallel token matching** (disabled by default): If desired, spin up a ThreadPool to fan out token scans over pre-sliced rule lines. (No extra Panorama sessions needed.)

Output:
- For each IP: matching **address objects**, **address-groups**, **Security** rules, and **NAT** rules
- Writes stitched report to ./logs/results_YYYYmmdd_HHMMSS.txt

Notes:
- This matches **literal IPs** in address objects (ip-netmask). To support CIDR/range containment (IP ∈ object), toggle `ENABLE_CIDR_CONTAINMENT`.
- Tested with large configs; memory use proportional to config size.
"""

import os, re, logging, datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from ipaddress import ip_address, ip_network

# ========= USER SETTINGS =========
USERNAME = "admin"
PASSWORD = "REPLACE_ME"
PANORAMA_HOST = "10.232.240.150"

IPS_TO_CHECK = [
    "10.232.64.10",
    "10.212.64.10",
    "10.232.68.162",
    "10.212.68.162",
]

# Performance knobs
MAX_READ_TIMEOUT = 600          # allow full-config download
ENABLE_NETMIKO_DEBUG = True
PARALLEL_MATCH_WORKERS = 0      # 0 = disabled (local single-thread scans are already fast). Set to CPU count to enable.
ENABLE_CIDR_CONTAINMENT = False # if True, treat address objects with CIDR/range as containing an IP

LOG_DIR = "./logs"
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

# ---------- Panorama connect & full-config fetch ----------

def connect_panorama(host: str):
    info = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": USERNAME,
        "password": PASSWORD,
        "fast_cli": False,
        "global_delay_factor": 1.0,
        "session_log": _session_log_path(host, "panorama"),
    }
    try:
        conn = ConnectHandler(**info)
        conn.send_command("set cli config-output-format set", expect_string=r">|#")
        conn.send_command("set cli pager off", expect_string=r">|#")
        conn.send_command("set cli terminal width 999", expect_string=r">|#")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise RuntimeError(f"Failed to connect to Panorama: {e}")


def fetch_config_set(conn) -> list[str]:
    """Pull the full running config once in `set` format and return list of lines."""
    conn.config_mode()
    txt = conn.send_command("show", expect_string=r"#", read_timeout=MAX_READ_TIMEOUT)
    conn.exit_config_mode()
    # Keep only `set ...` lines
    lines = [ln.strip() for ln in txt.splitlines() if ln.strip().startswith("set ")]
    # Optional: persist raw for troubleshooting
    with open(os.path.join(LOG_DIR, "panorama_config_set.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return lines

# ---------- Parsers & Indexes ----------

ADDR_RE = re.compile(r"^set\s+(shared|device-group\s+[^\s]+)\s+address\s+([^\s]+)\s+ip-netmask\s+([^\s]+)")
GRP_RE  = re.compile(r"^set\s+(shared|device-group\s+[^\s]+)\s+address-group\s+([^\s]+)\s+static\s+\[(.+)\]")
SEC_RE  = re.compile(r"^set\s+device-group\s+([^\s]+)\s+(pre-rulebase|post-rulebase)\s+security\s+rules\s+([^\s]+)\s+(.+)$")
NAT_RE  = re.compile(r"^set\s+device-group\s+([^\s]+)\s+(pre-rulebase|post-rulebase)\s+nat\s+rules\s+([^\s]+)\s+(.+)$")

# classify helpers (string contains checks)

def _sec_field(s: str) -> str:
    s = f" {s} "
    if " source " in s: return "source"
    if " destination " in s: return "destination"
    if " from " in s: return "from-zone"
    if " to " in s: return "to-zone"
    if " service " in s: return "service"
    return "unknown"


def _nat_field(s: str) -> str:
    s = f" {s} "
    if " original-packet source " in s: return "original-source"
    if " original-packet destination " in s: return "original-destination"
    if " destination-translation translated-address " in s or " destination-translation dynamic-dns " in s: return "dst-translation"
    if " source-translation static-ip " in s or " source-translation translated-address " in s or " source-translation dynamic-ip-and-port " in s: return "src-translation"
    if " to-interface " in s: return "to-interface"
    if " service " in s: return "service"
    return "unknown"


class PanoramaIndex:
    def __init__(self, set_lines: list[str]):
        self.set_lines = set_lines
        # Address objects
        self.addr_by_ip: dict[str, list[tuple[str,str,str]]] = {}   # ip -> [(name, scope, raw)]
        self.addr_meta: dict[str, tuple[str,str,str]] = {}          # name -> (ip_spec, scope, raw)
        # Address-groups (static)
        self.group_members: dict[str, tuple[list[str], str]] = {}   # name -> ([members], scope)
        # Security & NAT rule lines
        self.sec_lines: list[tuple[str,str,str,str]] = []           # (dg, where, rule, tail)
        self.nat_lines: list[tuple[str,str,str,str]] = []
        self._build()

    def _build(self):
        for ln in self.set_lines:
            m = ADDR_RE.match(ln)
            if m:
                scope, name, ip_spec = m.group(1), m.group(2), m.group(3)
                self.addr_meta[name] = (ip_spec, scope, ln)
                # literal map on exact token (e.g., 1.2.3.4 or 1.2.3.0/24)
                self.addr_by_ip.setdefault(ip_spec, []).append((name, scope, ln))
                continue
            m = GRP_RE.match(ln)
            if m:
                scope, name, inside = m.group(1), m.group(2), m.group(3)
                members = [t.strip().strip(",") for t in inside.split() if t.strip() not in ("[", "]")]
                self.group_members[name] = (members, scope)
                continue
            m = SEC_RE.match(ln)
            if m:
                dg, where, rule, tail = m.groups()
                self.sec_lines.append((dg, where, rule, tail))
                continue
            m = NAT_RE.match(ln)
            if m:
                dg, where, rule, tail = m.groups()
                self.nat_lines.append((dg, where, rule, tail))
                continue

    # containment-aware lookup of address objects for a given IP
    def addr_objects_for_ip(self, ip: str) -> list[dict]:
        out = []
        seen = set()
        # literal matches first (fast)
        for key in (ip, f"{ip}/32"):
            for name, scope, raw in self.addr_by_ip.get(key, []):
                if name not in seen:
                    seen.add(name)
                    out.append({"name": name, "scope": scope})
        if ENABLE_CIDR_CONTAINMENT:
            ip_obj = ip_address(ip)
            for name, (ip_spec, scope, raw) in self.addr_meta.items():
                if name in seen: continue
                if "/" in ip_spec:
                    try:
                        if ip_obj in ip_network(ip_spec, strict=False):
                            seen.add(name)
                            out.append({"name": name, "scope": scope})
                    except Exception:
                        pass
        return out

    def groups_containing_any(self, obj_names: list[str]) -> list[dict]:
        out, seen = [], set()
        targets = set(obj_names)
        for gname, (members, scope) in self.group_members.items():
            if targets.intersection(members):
                key = (gname, scope)
                if key not in seen:
                    seen.add(key)
                    out.append({"name": gname, "scope": scope})
        return out

    # Generic matcher over prepared rule lines
    def _match_rules(self, lines: list[tuple[str,str,str,str]], tokens: set[str], classifier) -> list[dict]:
        results = []
        def scan_slice(slice_iter):
            tmp = []
            for (dg, where, rule, tail) in slice_iter:
                hay = f" {tail} "
                matched = [t for t in tokens if f" {t} " in hay]
                if matched:
                    field = classifier(tail)
                    tmp.append({"tokens": matched, "dg": dg, "where": where, "rule": rule, "field": field})
            return tmp
        if PARALLEL_MATCH_WORKERS and PARALLEL_MATCH_WORKERS > 0:
            # slice lines into roughly-even chunks
            chunks = []
            n = max(1, len(lines) // PARALLEL_MATCH_WORKERS)
            for i in range(0, len(lines), n):
                chunks.append(lines[i:i+n])
            with ThreadPoolExecutor(max_workers=PARALLEL_MATCH_WORKERS) as ex:
                futs = [ex.submit(scan_slice, ch) for ch in chunks]
                for fut in as_completed(futs):
                    results.extend(fut.result())
        else:
            results = scan_slice(lines)
        # de-dup
        seen = set()
        out = []
        for r in results:
            key = (tuple(sorted(r["tokens"])), r["dg"], r["where"], r["rule"], r["field"])
            if key not in seen:
                seen.add(key)
                out.append(r)
        return out

    def security_refs(self, tokens: set[str]) -> list[dict]:
        return self._match_rules(self.sec_lines, tokens, _sec_field)

    def nat_refs(self, tokens: set[str]) -> list[dict]:
        return self._match_rules(self.nat_lines, tokens, _nat_field)


# ---------- Pretty printers ----------

def _lines_section_header(ip: str):
    return [f"===== IP: {ip} ====="]

def _lines_addr_objs(objs):
    if objs:
        return ["Address object(s):"] + [f"  - {o['name']} ({o['scope']})" for o in objs]
    return ["Address object(s): <none found>"]

def _lines_groups(groups):
    if groups:
        return ["Address-group(s) containing the object(s):"] + [f"  - {g['name']} ({g['scope']})" for g in groups]
    return ["Address-group(s) containing the object(s): <none>"]

def _collapse_rule_refs(refs):
    agg = {}
    for r in refs:
        key = (r["dg"], r["where"], r["rule"]) 
        ent = agg.setdefault(key, {"fields": set(), "tokens": set()})
        ent["fields"].add(r["field"])
        for t in r.get("tokens", []):
            ent["tokens"].add(t)
    out = []
    for (dg, where, rule), v in sorted(agg.items()):
        fields = ",".join(sorted(v["fields"]))
        toks = ",".join(sorted(v["tokens"]))
        out.append(f"  - DG={dg:<14} {where:<12} rule={rule:<40} fields=[{fields}] via=[{toks}]")
    return out

def _lines_security(refs):
    return (["Security rules referencing the IP/object/group:"] + _collapse_rule_refs(refs)) if refs else ["Security rules referencing the IP/object/group: <none>"]

def _lines_nat(refs):
    return (["NAT rules referencing the IP/object/group:"] + _collapse_rule_refs(refs)) if refs else ["NAT rules referencing the IP/object/group: <none>"]

# ---------- main ----------

def main():
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = os.path.join(LOG_DIR, f"results_{ts}.txt")

    print("\n=== Panorama IP Audit (FAST) ===")
    print(f"Panorama: {PANORAMA_HOST}")
    print(f"IPs: {', '.join(IPS_TO_CHECK)}")
    print(f"Logs dir: {os.path.abspath(LOG_DIR)}\n")

    pano = connect_panorama(PANORAMA_HOST)
    set_lines = fetch_config_set(pano)
    pano.disconnect()

    index = PanoramaIndex(set_lines)

    out_lines = []
    for ip in IPS_TO_CHECK:
        out_lines += _lines_section_header(ip)
        objs = index.addr_objects_for_ip(ip)
        out_lines += _lines_addr_objs(objs)
        groups = index.groups_containing_any([o["name"] for o in objs])
        out_lines += _lines_groups(groups)

        tokens = {ip}
        tokens.update([o["name"] for o in objs])
        tokens.update([g["name"] for g in groups])

        sec_refs = index.security_refs(tokens)
        nat_refs = index.nat_refs(tokens)
        out_lines += _lines_security(sec_refs)
        out_lines += _lines_nat(nat_refs)
        out_lines.append("")

    with open(results_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    print("\n".join(out_lines))
    print(f"\nSaved stitched report: {os.path.abspath(LOG_DIR)}/{os.path.basename(results_path)}")

if __name__ == "__main__":
    main()
