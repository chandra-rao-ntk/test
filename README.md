#!/usr/bin/env python3
# Read-only, parallel PAN workflow:
# - Panorama: find address objects & rules for multiple IPs (single session)
# - Firewalls: single session per FW; auto-detect VSYS->VRs; fib-lookup for ALL IPs; resolve Zone with caching
# - Checks ALL firewalls; stars (★) those whose DG has rules for the IP
# - Per-session logs + stitched report in ./logs/

import os
import logging
import datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS =========
USERNAME = "admin"
PASSWORD = "REPLACE_ME"

IPS_TO_CHECK = [
    "10.232.64.10",
    "10.212.64.10",
    "10.232.68.162",
    "10.212.68.162",
]

PANORAMA_HOST = "10.232.240.150"

# All firewalls (mgmt_ip -> friendly_name)
FIREWALLS = {
    "10.232.240.151": "FBAS21INFW001",
    "10.232.240.161": "FBAS21NPFW001",
    "10.232.240.155": "FBAS21PAFW001",
    "10.232.240.159": "FBAS21PRFW001",
    "10.232.240.153": "FBAS21SSFW001",
    "10.232.240.157": "FBAS21VPFW001",
    "10.212.240.151": "FBCH03INFW001",
    "10.212.240.161": "FBCH03NPFW001",
    "10.212.240.155": "FBCH03PAFW001",
    "10.212.240.159": "FBCH03PRFW001",
    "10.212.240.153": "FBCH03SSFW001",
    "10.212.240.157": "FBCH03VPFW001",
}

# Map device-group -> firewall mgmt IP(s) (edit to match your Panorama DGs)
DG_TO_FIREWALLS = {
    "FBAS21INFW": ["10.232.240.151"],
    "FBAS21NPFW": ["10.232.240.161"],
    "FBAS21PAFW": ["10.232.240.155"],
    "FBAS21PRFW": ["10.232.240.159"],
    "FBAS21SSFW": ["10.232.240.153"],
    "FBAS21VPFW": ["10.232.240.157"],
    "FBCH03INFW": ["10.212.240.151"],
    "FBCH03NPFW": ["10.212.240.161"],
    "FBCH03PAFW": ["10.212.240.155"],
    "FBCH03PRFW": ["10.212.240.159"],
    "FBCH03SSFW": ["10.212.240.153"],
    "FBCH03VPFW": ["10.212.240.157"],
}

# Concurrency for firewall checks (one session per FW)
MAX_WORKERS = 10

# Logging
LOG_DIR = "./logs"
ENABLE_NETMIKO_DEBUG = True
os.makedirs(LOG_DIR, exist_ok=True)
if ENABLE_NETMIKO_DEBUG:
    logging.basicConfig(
        filename=os.path.join(LOG_DIR, "netmiko_debug.log"),
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("netmiko").setLevel(logging.DEBUG)


# ---------- small utils ----------

def _session_log_path(host: str, kind: str) -> str:
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return os.path.join(LOG_DIR, f"{kind}_{host.replace(':','_')}_{ts}.session.log")

def _write_log(fname: str, text: str):
    try:
        with open(os.path.join(LOG_DIR, fname), "w", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass


# ---------- Netmiko connect ----------

def connect_panos(host, title=""):
    info = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": USERNAME,
        "password": PASSWORD,
        "fast_cli": False,
        "global_delay_factor": 1.0,
        "session_log": _session_log_path(host, "panorama" if host == PANORAMA_HOST else "fw"),
    }
    try:
        conn = ConnectHandler(**info)
        # set once at session start (avoid "Invalid syntax" when inside config-mode)
        conn.send_command("set cli config-output-format set", expect_string=r">|#")
        conn.send_command("set cli pager off", expect_string=r">|#")
        conn.send_command("set cli terminal width 500", expect_string=r">|#")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise RuntimeError(f"Failed to connect to {title or host}: {e}")


# ---------- Panorama (SSH, set-format) ----------

def pano_get_address_objects_for_ip(conn, ip):
    """Return [{'name': NAME, 'scope': 'shared'|'device-group <DG>'}, ...]"""
    conn.config_mode()
    out = conn.send_command(f"show | match {ip}", expect_string=r"#", read_timeout=90)
    conn.exit_config_mode()

    objs, seen = [], set()
    for s in out.splitlines():
        s = s.strip()
        if not (s.startswith("set ") and " address " in s and " ip-netmask " in s and ip in s):
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


def pano_get_rules_for_object(conn, obj_name):
    """Return [{'obj':name,'dg':DG,'where':pre|post|rulebase,'rule':RULE,'field':source|destination}, ...]"""
    conn.config_mode()
    out = conn.send_command(f"show | match {obj_name}", expect_string=r"#", read_timeout=90)
    conn.exit_config_mode()

    refs, seen = [], set()
    for s in out.splitlines():
        s = s.strip()
        if not s.startswith("set device-group ") or " security rules " not in s or f" {obj_name} " not in f" {s} ":
            continue
        parts = s.split()
        try:
            dg     = parts[2]
            where  = parts[3]
            rule   = parts[parts.index("rules") + 1]
            field  = "source" if " source " in f" {s} " else ("destination" if " destination " in f" {s} " else "unknown")
            key    = (obj_name, dg, where, rule, field)
            if key not in seen:
                seen.add(key)
                refs.append({"obj": obj_name, "dg": dg, "where": where, "rule": rule, "field": field})
        except Exception:
            continue
    return refs


# ---------- Firewall (SSH): VSYS & VR discovery + multi-IP routing/zone ----------

def discover_vsys(conn):
    """Return a sorted list of vsys names (e.g., ['vsys1', 'vsys2'])."""
    conn.config_mode()
    out = conn.send_command('show | match "set vsys "', expect_string=r"#", read_timeout=60)
    conn.exit_config_mode()
    vsys = set()
    for line in out.splitlines():
        parts = line.strip().split()
        # lines start with: set vsys <vsysName> ...
        if len(parts) >= 3 and parts[0] == "set" and parts[1] == "vsys":
            vsys.add(parts[2])
    if not vsys:
        vsys.add("vsys1")
    return sorted(vsys)


def vrs_for_vsys(conn, vsys):
    """
    Return VRs imported into this VSYS:
      set vsys <vsys> import network virtual-router <VR>
    Fallback to global VR list if none found.
    """
    conn.config_mode()
    out = conn.send_command(f'show | match "set vsys {vsys} import network virtual-router "', expect_string=r"#", read_timeout=60)
    if not out.strip():
        out = conn.send_command('show | match "set network virtual-router "', expect_string=r"#", read_timeout=60)
    conn.exit_config_mode()

    vrs = set()
    for line in out.splitlines():
        parts = line.strip().split()
        # either: set vsys <vsys> import network virtual-router <VR>
        # or:     set network virtual-router <VR> ...
        if len(parts) >= 6 and parts[:5] == ["set", "vsys", vsys, "import", "network"] and parts[5] == "virtual-router":
            if len(parts) >= 7:
                vrs.add(parts[6])
        elif len(parts) >= 4 and parts[:3] == ["set", "network", "virtual-router"]:
            vrs.add(parts[3])
    return sorted(vrs)


def set_target_vsys(conn, vsys):
    conn.send_command(f"set system setting target-vsys {vsys}", expect_string=r">|#")

def reset_target_vsys(conn):
    conn.send_command("set system setting target-vsys none", expect_string=r">|#")


def _clean_iface(token: str) -> str:
    return token.strip().strip(",;:")


def fib_try(conn, vr, ip):
    out = conn.send_command(f"test routing fib-lookup virtual-router {vr} ip {ip}", read_timeout=45)
    first, selected = None, None
    for raw in out.splitlines():
        line = raw.strip()
        if "interface " in line:
            try:
                iface = _clean_iface(line.split("interface", 1)[1].split()[0])
            except Exception:
                continue
            if first is None:
                first = iface
            if "[selected]" in line:
                selected = iface
    return selected or first


def fib_lookup_multi(conn, ips):
    """
    Efficient multi-IP routing:
      - Discover VSYS list and VRs once
      - Loop VSYS -> (set target) -> try VRs for all unresolved IPs
    Returns dict ip -> (iface, vr, vsys) or None-triples if not found
    """
    results = {ip: (None, None, None) for ip in ips}
    unresolved = set(ips)

    vsys_list = discover_vsys(conn)
    vsys_to_vrs = {}

    for vsys in vsys_list:
        try:
            set_target_vsys(conn, vsys)
        except Exception:
            continue

        if vsys not in vsys_to_vrs:
            vsys_to_vrs[vsys] = vrs_for_vsys(conn, vsys)
        vrs = vsys_to_vrs[vsys]

        # For each unresolved IP, try VRs
        for ip in list(unresolved):
            found_iface = None
            for vr in vrs:
                iface = fib_try(conn, vr, ip)
                if iface:
                    results[ip] = (iface, vr, vsys)
                    found_iface = iface
                    break
            if found_iface:
                unresolved.discard(ip)

        if not unresolved:
            break

    reset_target_vsys(conn)
    return results


def _parse_zone_line(line: str):
    s = line.strip()
    idx = s.lower().find("zone")
    if idx == -1:
        return None
    tail = s[idx + len("zone"):].lstrip(" :=\t")
    zone = tail.split(",", 1)[0].strip()
    return zone or None


def get_zone_for_interface(conn, fw_host: str, interface: str):
    if not interface:
        return None

    cmd1 = f"show interface {interface} | match Zone"
    out1 = conn.send_command(cmd1, read_timeout=30)
    for line in out1.splitlines():
        z = _parse_zone_line(line)
        if z:
            return z

    cmd2 = f"show interface {interface} | match zone"
    out2 = conn.send_command(cmd2, read_timeout=30)
    for line in out2.splitlines():
        z = _parse_zone_line(line)
        if z:
            return z

    # Final fallback: config scrape
    conn.config_mode()
    cmd3 = f"show | match zone | match {interface}"
    out3 = conn.send_command(cmd3, expect_string=r"#", read_timeout=60)
    conn.exit_config_mode()
    for s in out3.splitlines():
        s = s.strip()
        if s.startswith("set ") and " zone " in s and interface in s:
            try:
                zone = s.split(" zone ", 1)[1].split()[0]
                if zone:
                    return zone
            except Exception:
                pass

    debug_text = f"$ {cmd1}\n{out1}\n\n$ {cmd2}\n{out2}\n\n$ {cmd3}\n{out3}\n"
    _write_log(f"{fw_host}_zone_debug_{interface}.txt", debug_text)
    return None


# ---------- Workers & orchestration ----------

def fw_worker_all_ips(fw_ip, fw_name, ip_list):
    """
    Single connection per firewall:
      - auto VSYS/VR discovery
      - fib-lookup for ALL IPs
      - cache interface->zone
    Returns: dict[ip] = {fw, ip, vsys, vr, iface, zone, err}
    """
    res = {}
    try:
        fw = connect_panos(fw_ip, fw_name)

        # Multi-IP routing in one go
        routing = fib_lookup_multi(fw, ip_list)  # ip -> (iface, vr, vsys)

        # Cache zones by interface so we only query once per interface
        zone_cache = {}
        for ip in ip_list:
            iface, vr, vsys = routing.get(ip, (None, None, None))
            zone = None
            if iface:
                if iface in zone_cache:
                    zone = zone_cache[iface]
                else:
                    zone = get_zone_for_interface(fw, fw_ip, iface)
                    zone_cache[iface] = zone
            res[ip] = {
                "fw": fw_name, "ip": fw_ip,
                "vsys": vsys or "<unknown>", "vr": vr or "<unknown>",
                "iface": iface or "<not-found>", "zone": zone or "<not-found>", "err": ""
            }

        fw.disconnect()
        return res

    except Exception as e:
        for ip in ip_list:
            res[ip] = {"fw": fw_name, "ip": fw_ip, "vsys": "<error>", "vr": "<error>", "iface": "<error>", "zone": "<error>", "err": str(e)}
        return res


def dgs_for_rule_refs(rule_refs):
    return {r["dg"] for r in rule_refs}

def starred_fw_ips_from_dgs(rule_dgs):
    starred = set()
    for dg in rule_dgs:
        for ip in DG_TO_FIREWALLS.get(dg, []):
            starred.add(ip)
    return starred


def main():
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = os.path.join(LOG_DIR, f"results_{ts}.txt")

    print(f"\n=== PAN Multi-IP Lookup (single login per firewall) ===")
    print(f"Panorama: {PANORAMA_HOST}")
    print(f"IPs: {', '.join(IPS_TO_CHECK)}")
    print(f"Logs dir: {os.path.abspath(LOG_DIR)}\n")

    # ----- Panorama once -----
    pano = connect_panos(PANORAMA_HOST, "Panorama")

    ip_contexts = {}  # ip -> {"objects":[], "refs":[], "starred_fw_ips": set()}
    for ip in IPS_TO_CHECK:
        objs = pano_get_address_objects_for_ip(pano, ip)
        refs = []
        for o in objs:
            refs.extend(pano_get_rules_for_object(pano, o["name"]))
        dgs = dgs_for_rule_refs(refs)
        stars = starred_fw_ips_from_dgs(dgs)
        ip_contexts[ip] = {"objects": objs, "refs": refs, "starred_fw_ips": stars}

    pano.disconnect()

    # ----- Firewalls once each, process ALL IPs inside -----
    fw_results_all = {}  # fw_ip -> dict[ip] -> row
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(fw_worker_all_ips, fw_ip, fw_name, IPS_TO_CHECK): (fw_ip, fw_name)
                   for fw_ip, fw_name in FIREWALLS.items()}
        for fut in as_completed(futures):
            fw_ip, _ = futures[fut]
            fw_results_all[fw_ip] = fut.result()

    # ----- Build stitched report -----
    lines = []
    for ip in IPS_TO_CHECK:
        ctx = ip_contexts[ip]
        objs, refs, stars = ctx["objects"], ctx["refs"], ctx["starred_fw_ips"]

        lines.append(f"===== IP: {ip} =====")
        if objs:
            lines.append("Address object(s):")
            for o in objs:
                lines.append(f"  - {o['name']} ({o['scope']})")
        else:
            lines.append("Address object(s): <none found>")

        if refs:
            lines.append("Rules referencing the object name(s):")
            seen = set()
            for r in refs:
                key = (r['obj'], r['dg'], r['where'], r['rule'], r['field'])
                if key in seen:
                    continue
                seen.add(key)
                lines.append(f"  - OBJ={r['obj']:<24} DG={r['dg']:<14} {r['where']:<12} rule={r['rule']:<40} field={r['field']}")
        else:
            lines.append("Rules referencing the object name(s): <none>")

        lines.append("Per-firewall routing & zone (ALL FWs; ★ = DG has matching rules):")
        lines.append(f"{'Firewall':<20} {'Mgmt IP':<15} {'VSYS':<8} {'VR':<16} {'Interface':<18} {'Zone':<24} {'Error':<0}")
        lines.append("-" * 118)

        # Stitch rows by iterating all FWs and grabbing that FW's row for this IP
        for fw_ip, fw_name in sorted(FIREWALLS.items(), key=lambda kv: (kv[1], kv[0])):
            row = fw_results_all.get(fw_ip, {}).get(ip)
            if not row:
                row = {"fw": fw_name, "ip": fw_ip, "vsys": "<n/a>", "vr": "<n/a>", "iface": "<n/a>", "zone": "<n/a>", "err": "no data"}
            star = "★" if fw_ip in stars else " "
            fw_disp = f"{star} {row['fw']}"
            lines.append(f"{fw_disp:<20} {row['ip']:<15} {row['vsys']:<8} {row['vr']:<16} {row['iface']:<18} {row['zone']:<24} {row['err']}")

        lines.append("")

    with open(results_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print("\n".join(lines))
    print(f"\nSaved stitched report: {os.path.abspath(LOG_DIR)}/{os.path.basename(results_path)}")
    print("Legend: ★ = firewall's DG has rules referencing the IP's address object(s)\n")


if __name__ == "__main__":
    main()
