#!/usr/bin/env python3
"""
Panorama-only read-only workflow
- Logs into Panorama once (Netmiko CLI, set-output to 'set' format)
- For each IP in IPS_TO_CHECK:
    • Finds address objects (shared + DG) that map to the IP
    • Finds any address-groups that include those objects (static groups)
    • Finds security rules that reference the IP/object/group
    • Finds NAT rules that reference the IP/object/group (original/translated fields)
- Writes a stitched text report to ./logs/results_YYYYmmdd_HHMMSS.txt

NOTE: This uses CLI text scraping (no API keys required). It looks for direct string
matches of the IP or object/group names. If an object contains a CIDR/range that
*includes* the IP but doesn't literally mention it, this method may miss it.
"""

import os, re, logging, datetime as dt
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS =========
USERNAME = ""
PASSWORD = ""

PANORAMA_HOST = "10.21.128.226"

# Validate these IPs
IPS_TO_CHECK = [
"10.224.160.85",
]

MAX_READ_TIMEOUT = 120
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
        "fast_cli": False,
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


# ---------- Panorama lookups ----------

def pano_addr_objs_for_ip(conn, ip: str):
    """Return address objects that literally specify this IP via ip-netmask.
       Results: [{"name":..., "scope":"shared|device-group <DG>"}]"""
    conn.config_mode()
    out = conn.send_command(f"show | match {ip}", expect_string=r"#", read_timeout=MAX_READ_TIMEOUT)
    conn.exit_config_mode()

    objs, seen = [], set()
    for s in out.splitlines():
        s = s.strip()
        if not (s.startswith("set ") and " address " in s and " ip-netmask " in s and ip in s):
            # also match '/32' style (ip + '/32') — covered by "ip in s"
            continue
        parts = s.split()
        if parts[1] == "shared" and parts[2] == "address":
            name, scope = parts[3], "shared"
        elif parts[1] == "device-group":
            dg = parts[2]
            name = parts[parts.index("address") + 1]
            scope = f"device-group {dg}"
        else:
            continue
        key = (name, scope)
        if key not in seen:
            seen.add(key)
            objs.append({"name": name, "scope": scope})

    if not objs:
        _write_log(f"pano_show_match_{ip}.txt", out)
    return objs


def pano_groups_containing_object(conn, obj_name: str):
    """Return address-group names (shared or device-group) that include obj_name (static groups).
       Results: [{"name":..., "scope":...}]"""
    conn.config_mode()
    out = conn.send_command(f"show | match {obj_name}", expect_string=r"#", read_timeout=MAX_READ_TIMEOUT)
    conn.exit_config_mode()

    groups, seen = [], set()
    for s in out.splitlines():
        s = s.strip()
        if not (s.startswith("set ") and " address-group " in s and " static " in s and f" {obj_name} " in f" {s} "):
            continue
        parts = s.split()
        if parts[1] == "shared" and parts[2] == "address-group":
            name, scope = parts[3], "shared"
        elif parts[1] == "device-group":
            dg = parts[2]
            name = parts[parts.index("address-group") + 1]
            scope = f"device-group {dg}"
        else:
            continue
        key = (name, scope)
        if key not in seen:
            seen.add(key)
            groups.append({"name": name, "scope": scope})
    return groups


def _classify_sec_field(set_line: str) -> str:
    if " source " in f" {set_line} ":
        return "source"
    if " destination " in f" {set_line} ":
        return "destination"
    if " from " in f" {set_line} ":
        return "from-zone"
    if " to " in f" {set_line} ":
        return "to-zone"
    if " service " in f" {set_line} ":
        return "service"
    return "unknown"


def pano_security_refs_for_token(conn, token: str):
    """Find security rules that reference the given token (IP/object/group).
       Returns: list of {token, dg, where, rule, field}.
    """
    conn.config_mode()
    out = conn.send_command(f"show | match {token}", expect_string=r"#", read_timeout=MAX_READ_TIMEOUT)
    conn.exit_config_mode()

    refs, seen = [], set()
    for s in out.splitlines():
        s = s.strip()
        if not (s.startswith("set device-group ") and " security rules " in s and f" {token} " in f" {s} "):
            continue
        parts = s.split()
        try:
            dg = parts[2]
            where = parts[3]  # pre-rulebase | post-rulebase
            rule = parts[parts.index("rules") + 1]
            field = _classify_sec_field(s)
            key = (token, dg, where, rule, field)
            if key not in seen:
                seen.add(key)
                refs.append({"token": token, "dg": dg, "where": where, "rule": rule, "field": field})
        except Exception:
            continue
    return refs


def _classify_nat_field(set_line: str) -> str:
    t = f" {set_line} "
    if " original-packet source " in t:
        return "original-source"
    if " original-packet destination " in t:
        return "original-destination"
    if " destination-translation translated-address " in t or " destination-translation dynamic-dns " in t:
        return "dst-translation"
    if " source-translation static-ip " in t or " source-translation translated-address " in t or " source-translation dynamic-ip-and-port " in t:
        return "src-translation"
    if " to-interface " in t:
        return "to-interface"
    if " service " in t:
        return "service"
    return "unknown"


def pano_nat_refs_for_token(conn, token: str):
    """Find NAT rules that reference the given token (IP/object/group).
       Returns: list of {token, dg, where, rule, field}.
    """
    conn.config_mode()
    out = conn.send_command(f"show | match {token}", expect_string=r"#", read_timeout=MAX_READ_TIMEOUT)
    conn.exit_config_mode()

    refs, seen = [], set()
    for s in out.splitlines():
        s = s.strip()
        if not (s.startswith("set device-group ") and " nat rules " in s and f" {token} " in f" {s} "):
            continue
        parts = s.split()
        try:
            dg = parts[2]
            where = parts[3]  # pre-rulebase | post-rulebase
            rule = parts[parts.index("rules") + 1]
            field = _classify_nat_field(s)
            key = (token, dg, where, rule, field)
            if key not in seen:
                seen.add(key)
                refs.append({"token": token, "dg": dg, "where": where, "rule": rule, "field": field})
        except Exception:
            continue
    return refs


# ---------- report helpers ----------

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
    # refs: list of {token, dg, where, rule, field}
    # Collapse by (dg, where, rule) -> set(fields), set(tokens)
    agg = {}
    for r in refs:
        key = (r["dg"], r["where"], r["rule"]) 
        if key not in agg:
            agg[key] = {"fields": set(), "tokens": set()}
        agg[key]["fields"].add(r["field"])
        agg[key]["tokens"].add(r["token"])
    # pretty lines
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


# ---------- main ----------

def main():
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = os.path.join(LOG_DIR, f"results_{ts}.txt")

    print("\n=== Panorama IP Audit (addresses, NAT, security) ===")
    print(f"Panorama: {PANORAMA_HOST}")
    print(f"IPs: {', '.join(IPS_TO_CHECK)}")
    print(f"Logs dir: {os.path.abspath(LOG_DIR)}\n")

    pano = connect_panorama(PANORAMA_HOST)

    out_lines = []

    for ip in IPS_TO_CHECK:
        out_lines += _lines_section_header(ip)

        # 1) Address objects
        objs = pano_addr_objs_for_ip(pano, ip)
        out_lines += _lines_addr_objs(objs)

        # 2) For each object, find groups that contain it (static address-groups)
        all_groups = []
        for o in objs:
            groups = pano_groups_containing_object(pano, o["name"]) or []
            for g in groups:
                if g not in all_groups:
                    all_groups.append(g)
        out_lines += _lines_groups(all_groups)

        # Search tokens: the literal IP, object names, and any group names containing those objects
        tokens = {ip}
        tokens.update([o["name"] for o in objs])
        tokens.update([g["name"] for g in all_groups])

        # 3) Security rule refs (by IP, objects, groups)
        sec_refs = []
        for tok in sorted(tokens):
            sec_refs.extend(pano_security_refs_for_token(pano, tok))
        out_lines += _lines_security(sec_refs)

        # 4) NAT rule refs (by IP, objects, groups)
        nat_refs = []
        for tok in sorted(tokens):
            nat_refs.extend(pano_nat_refs_for_token(pano, tok))
        out_lines += _lines_nat(nat_refs)

        out_lines.append("")

    pano.disconnect()

    with open(results_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    print("\n".join(out_lines))
    print(f"\nSaved stitched report: {os.path.abspath(LOG_DIR)}/{os.path.basename(results_path)}")


if __name__ == "__main__":
    main()
