#!/usr/bin/env python3
# Read-only, parallel, DG-scoped PAN workflow with logs & stitched report

import os
import logging
import datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS =========
USERNAME = "admin"
PASSWORD = "REPLACE_ME"

# You can list as many IPs as you want here
IPS_TO_CHECK = [
    "10.232.64.10",
    # "10.1.2.3",
    # "10.4.5.6",
]

PANORAMA_HOST = "10.232.240.150"   # Panorama

# All firewalls you might target (mgmt_ip -> friendly_name)
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

# Map device-group name -> list of firewall mgmt IPs to check
# (Add/adjust DGs here. We matched based on your naming.)
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

# Seed VR names; we’ll also auto-discover all VRs on each firewall
VR_CANDIDATES = ["default", "VR-1", "vr1", "trust-vr", "untrust-vr"]

# Concurrency
MAX_WORKERS = 8  # tweak if you have more/less firewalls

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


def _session_log_path(host: str, kind: str) -> str:
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe = host.replace(":", "_")
    return os.path.join(LOG_DIR, f"{kind}_{safe}_{ts}.session.log")


# ---------------- Netmiko connect ----------------

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
        conn.send_command("set cli config-output-format set", expect_string=r">|#")
        conn.send_command("set cli pager off", expect_string=r">|#")
        conn.send_command("set cli terminal width 500", expect_string=r">|#")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise RuntimeError(f"Failed to connect to {title or host}: {e}")


# ------------- Panorama helpers (SSH, set-format) -------------

def pano_get_address_objects_for_ip(conn, ip):
    """Return [{'name': NAME, 'scope': 'shared'|'device-group <DG>'}, ...]"""
    conn.config_mode()
    conn.send_command("set cli pager off", expect_string=r"#")
    conn.send_command("set cli config-output-format set", expect_string=r"#")
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
        with open(os.path.join(LOG_DIR, f"pano_show_match_{ip}.txt"), "w", encoding="utf-8") as f:
            f.write(out)
    return objs


def pano_get_rules_for_object(conn, obj_name):
    """Return [{'obj':name,'dg':DG,'where':pre|post|rulebase,'rule':RULE,'field':source|destination}, ...]"""
    conn.config_mode()
    conn.send_command("set cli pager off", expect_string=r"#")
    conn.send_command("set cli config-output-format set", expect_string=r"#")
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


# ------------- Firewall helpers (SSH) -------------

def discover_vrs(conn):
    """Find all VR names on a firewall."""
    conn.config_mode()
    conn.send_command("set cli config-output-format set", expect_string=r"#")
    out = conn.send_command('show | match "set network virtual-router "', expect_string=r"#", read_timeout=60)
    conn.exit_config_mode()
    vrs = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and parts[:3] == ["set", "network", "virtual-router"]:
            vrs.append(parts[3])
    return sorted(set(vrs))


def fib_lookup_any_vr(conn, ip):
    """Try candidates then discovered VRs. Return (iface, vr_used)."""
    tried = set()
    for vr in VR_CANDIDATES:
        iface = _fib_try(conn, vr, ip)
        tried.add(vr)
        if iface:
            return iface, vr
    for vr in discover_vrs(conn):
        if vr in tried:
            continue
        iface = _fib_try(conn, vr, ip)
        if iface:
            return iface, vr
    return None, None


def _fib_try(conn, vr, ip):
    out = conn.send_command(f"test routing fib-lookup virtual-router {vr} ip {ip}", read_timeout=45)
    first, selected = None, None
    for raw in out.splitlines():
        line = raw.strip()
        if "interface " in line:
            try:
                iface = line.split("interface", 1)[1].split()[0]
            except Exception:
                continue
            if first is None:
                first = iface
            if "[selected]" in line:
                selected = iface
    return selected or first


def get_zone_for_interface(conn, interface):
    if not interface:
        return None
    out = conn.send_command(f"show interface {interface}", read_timeout=30)
    for line in out.splitlines():
        if line.strip().startswith("Zone:"):
            after = line.split("Zone:", 1)[1].strip()
            return after.split(",", 1)[0].strip()
    return None


# ------------- Workers & Orchestration -------------

def fw_worker(fw_ip, fw_name, ip):
    """Connect to one firewall and resolve zone for one IP."""
    try:
        fw = connect_panos(fw_ip, fw_name)
        iface, vr = fib_lookup_any_vr(fw, ip)
        zone = get_zone_for_interface(fw, iface)
        fw.disconnect()
        return {
            "fw": fw_name, "ip": fw_ip, "vr": vr or "<unknown>",
            "iface": iface or "<not-found>", "zone": zone or "<not-found>", "err": ""
        }
    except Exception as e:
        return {"fw": fw_name, "ip": fw_ip, "vr": "<error>", "iface": "<error>", "zone": "<error>", "err": str(e)}


def map_dgs_to_firewalls(dg_names):
    """Resolve which firewall IPs to check from a set of DG names."""
    targets = set()
    for dg in dg_names:
        if dg in DG_TO_FIREWALLS:
            for ip in DG_TO_FIREWALLS[dg]:
                targets.add(ip)
        else:
            # Best-effort guess: use any firewall whose friendly name contains the DG token
            for ip, fname in FIREWALLS.items():
                if dg in fname:
                    targets.add(ip)
    return sorted(targets)


def main():
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = os.path.join(LOG_DIR, f"results_{ts}.txt")

    print(f"\n=== PAN Multi-IP Lookup ===\nPanorama: {PANORAMA_HOST}\nIPs: {', '.join(IPS_TO_CHECK)}\nLogs dir: {os.path.abspath(LOG_DIR)}\n")

    # Connect to Panorama once
    pano = connect_panos(PANORAMA_HOST, "Panorama")

    report_lines = []
    for ip in IPS_TO_CHECK:
        # 1) Panorama → objects
        objs = pano_get_address_objects_for_ip(pano, ip)

        # 2) Panorama → rules for each object
        all_refs = []
        for o in objs:
            all_refs.extend(pano_get_rules_for_object(pano, o["name"]))

        # Device-groups referenced by rules
        dgs = sorted({r["dg"] for r in all_refs})

        # Which firewalls to check (DG scoped)
        target_fw_ips = map_dgs_to_firewalls(dgs)

        # 3) Parallel firewall checks for THIS IP
        futures = []
        results = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for fw_ip in target_fw_ips:
                futures.append(ex.submit(fw_worker, fw_ip, FIREWALLS[fw_ip], ip))
            for fut in as_completed(futures):
                results.append(fut.result())

        # 4) Build report section for this IP
        report_lines.append(f"===== IP: {ip} =====")
        if objs:
            report_lines.append("Address object(s):")
            for o in objs:
                report_lines.append(f"  - {o['name']} ({o['scope']})")
        else:
            report_lines.append("Address object(s): <none found>")

        if all_refs:
            report_lines.append("Rules referencing the object name(s):")
            seen = set()
            for r in all_refs:
                key = (r['obj'], r['dg'], r['where'], r['rule'], r['field'])
                if key in seen:
                    continue
                seen.add(key)
                report_lines.append(
                    f"  - OBJ={r['obj']:<24} DG={r['dg']:<14} {r['where']:<12} rule={r['rule']:<40} field={r['field']}"
                )
        else:
            report_lines.append("Rules referencing the object name(s): <none>")

        if target_fw_ips:
            report_lines.append("Per-firewall routing & zone (DG-scoped):")
            report_lines.append(f"{'Firewall':<18} {'Mgmt IP':<15} {'VR':<16} {'Interface':<18} {'Zone':<24} {'Error':<0}")
            report_lines.append("-" * 96)
            for r in sorted(results, key=lambda x: (x["fw"], x["ip"])):
                report_lines.append(
                    f"{r['fw']:<18} {r['ip']:<15} {r['vr']:<16} {r['iface']:<18} {r['zone']:<24} {r['err']}"
                )
        else:
            report_lines.append("No device-groups matched; skipped firewall checks for this IP.")

        report_lines.append("")  # blank line between IP sections

    pano.disconnect()

    # Write stitched report
    with open(results_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    # Also print to screen
    print("\n".join(report_lines))
    print(f"\nSaved stitched report: {os.path.abspath(results_path)}\n")


if __name__ == "__main__":
    main()
