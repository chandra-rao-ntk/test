#!/usr/bin/env python3
# Read-only PAN workflow:
# - Panorama: for multiple IPs, get address objects + rules AND discover VRs per template
# - Firewalls: one session per FW; use Panorama VR list to fib-lookup ALL IPs; cache interface->zone
# - Show ALL firewalls; star (★) rows whose DG has rules for the IP
# - Per-session logs + stitched report in ./logs/

import os
import re
import logging
import datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS =========
USERNAME = "admin"
PASSWORD = "REPLACE_ME"

IPS_TO_CHECK = [
    "10.232.64.10",
    # add more IPs here...
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

# OPTIONAL: if any firewall maps to a template name that doesn't follow the heuristic,
# specify it here (mgmt_ip -> template_name)
TEMPLATE_OVERRIDE = {
    # "10.232.240.151": "FBAS21INFW_Template",
}

# Device-group -> firewall mgmt IPs (used only to star rows in the table)
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

MAX_WORKERS = 10  # one session per FW

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

def _clean_iface(tok: str) -> str:
    return tok.strip().strip(",;:")


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
        conn.send_command("set cli config-output-format set", expect_string=r">|#")
        conn.send_command("set cli pager off", expect_string=r">|#")
        conn.send_command("set cli terminal width 999", expect_string=r">|#")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise RuntimeError(f"Failed to connect to {title or host}: {e}")


# ---------- Panorama lookups ----------

def pano_addr_objs_for_ip(conn, ip):
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


def pano_rules_for_object(conn, obj_name):
    """Return [{'obj', 'dg', 'where', 'rule', 'field'}, ...]"""
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


def pano_template_vrs(conn):
    """
    Parse Panorama config for VRs imported to vsys1 per template.
    Accepts either single VR or bracket list: [ INT_VR EXT_VR ].
    Returns: { 'FBAS21NPFW_Template': ['default'], 'FBCH03PAFW_Template': ['INT_VR','EXT_VR'], ... }
    """
    conn.config_mode()
    # match lines like: set template X config vsys vsys1 import network virtual-router <VR or [ A B ]>
    out = conn.send_command('show | match "set template " | match " vsys vsys1 import network virtual-router "', expect_string=r"#", read_timeout=90)
    conn.exit_config_mode()

    mapping = {}
    for line in out.splitlines():
        s = line.strip()
        if not s.startswith("set template ") or " vsys vsys1 import network virtual-router " not in s:
            continue
        parts = s.split()
        # set template <T> config vsys vsys1 import network virtual-router ...
        tmpl = parts[2]
        # after "... virtual-router", either a token or a bracketed list [...]
        tail = s.split("virtual-router", 1)[1].strip()
        vrs = []
        if tail.startswith("["):
            # collect tokens inside [...]
            inside = tail.strip("[]").strip()
            vrs = [tok.strip() for tok in inside.split() if tok.strip() not in ("[", "]")]
        else:
            vrs = [tail.split()[0]]
        # normalize
        vrs = [vr.strip(",") for vr in vrs if vr]
        if tmpl not in mapping:
            mapping[tmpl] = []
        for vr in vrs:
            if vr not in mapping[tmpl]:
                mapping[tmpl].append(vr)
    if not mapping:
        _write_log("pano_template_vrs_raw.txt", out)
    return mapping


def heuristic_template_name(fw_name: str) -> str:
    """
    Guess template name from FW name by stripping trailing digits and appending _Template.
    e.g. FBAS21NPFW001 -> FBAS21NPFW_Template
    """
    base = re.sub(r"\d+$", "", fw_name)
    return f"{base}_Template"


def build_fw_to_vrs_from_panorama(conn):
    """
    Use Panorama to map each firewall (by mgmt IP) to its VR list.
    We pick the template name by override or heuristic from the FW friendly name.
    Returns: { mgmt_ip: [vr1, vr2, ...], ... }
    """
    tmpl_vrs = pano_template_vrs(conn)

    fw_to_vrs = {}
    for mgmt_ip, fw_name in FIREWALLS.items():
        if mgmt_ip in TEMPLATE_OVERRIDE:
            tmpl = TEMPLATE_OVERRIDE[mgmt_ip]
        else:
            tmpl = heuristic_template_name(fw_name)
        vrs = tmpl_vrs.get(tmpl, [])
        fw_to_vrs[mgmt_ip] = vrs[:]  # copy
    return fw_to_vrs


# ---------- Firewall ops ----------

def discover_vrs_on_fw(conn):
    """
    Fallback VR discovery from the firewall itself (op-mode first, then config-mode).
    """
    vrs = set()

    out1 = conn.send_command("show routing summary", read_timeout=30)
    for line in out1.splitlines():
        m = re.search(r"\bvirtual[-\s]?router\s+([A-Za-z0-9._-]+)", line, re.IGNORECASE)
        if m:
            vrs.add(m.group(1))

    if not vrs:
        conn.config_mode()
        out2 = conn.send_command('show | match "set network virtual-router "', expect_string=r"#", read_timeout=60)
        conn.exit_config_mode()
        for line in out2.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4 and parts[:3] == ["set", "network", "virtual-router"]:
                vrs.add(parts[3])

    if not vrs:
        vrs.add("default")
    return sorted(vrs)


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


def fib_lookup_multi_using_vrs(conn, ips, vrs):
    """
    For a given firewall, try ONLY the VRs provided (from Panorama template).
    If the list is empty, fall back to discovering VRs on the FW.
    Returns: {ip: (iface, vr)}
    """
    results = {ip: (None, None) for ip in ips}
    unresolved = set(ips)

    vr_list = vrs[:] if vrs else discover_vrs_on_fw(conn)

    for vr in vr_list:
        if not unresolved:
            break
        for ip in list(unresolved):
            iface = fib_try(conn, vr, ip)
            if iface:
                results[ip] = (iface, vr)
                unresolved.discard(ip)

    return results


def get_zone_for_interface(conn, fw_host: str, interface: str):
    if not interface:
        return None
    cmd1 = f"show interface {interface} | match Zone"
    out1 = conn.send_command(cmd1, read_timeout=30)
    for line in out1.splitlines():
        s = line.strip()
        if s.lower().startswith("zone"):
            # Accept "Zone: NAME" or "zone: NAME"
            zone = s.split(":", 1)[-1].strip().split(",", 1)[0].strip()
            if zone:
                return zone

    cmd2 = f"show interface {interface} | match zone"
    out2 = conn.send_command(cmd2, read_timeout=30)
    for line in out2.splitlines():
        s = line.strip()
        if s.lower().startswith("zone"):
            zone = s.split(":", 1)[-1].strip().split(",", 1)[0].strip()
            if zone:
                return zone

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


def fw_worker_all_ips(fw_ip, fw_name, ip_list, pano_vrs_for_fw):
    """
    Single connection per firewall:
      - Use Panorama-provided VR list (fallback to local discovery)
      - FIB for ALL IPs
      - Cache interface->zone
    Returns: dict[ip] -> row
    """
    res = {}
    try:
        fw = connect_panos(fw_ip, fw_name)

        routing = fib_lookup_multi_using_vrs(fw, ip_list, pano_vrs_for_fw)  # ip -> (iface, vr)
        zone_cache = {}
        for ip in ip_list:
            iface, vr = routing.get(ip, (None, None))
            zone = None
            if iface:
                if iface in zone_cache:
                    zone = zone_cache[iface]
                else:
                    zone = get_zone_for_interface(fw, fw_ip, iface)
                    zone_cache[iface] = zone
            res[ip] = {
                "fw": fw_name, "ip": fw_ip,
                "vr": vr or "<unknown>",
                "iface": iface or "<not-found>", "zone": zone or "<not-found>", "err": ""
            }

        fw.disconnect()
        return res

    except Exception as e:
        for ip in ip_list:
            res[ip] = {"fw": fw_name, "ip": fw_ip, "vr": "<error>", "iface": "<error>", "zone": "<error>", "err": str(e)}
        return res


# ---------- stars and report ----------

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

    print(f"\n=== PAN Multi-IP Lookup (Panorama VR discovery) ===")
    print(f"Panorama: {PANORAMA_HOST}")
    print(f"IPs: {', '.join(IPS_TO_CHECK)}")
    print(f"Logs dir: {os.path.abspath(LOG_DIR)}\n")

    # -------- Panorama once: objects+rules and VRs per template --------
    pano = connect_panos(PANORAMA_HOST, "Panorama")

    # Build VR list per firewall from Panorama templates
    fw_to_vrs = build_fw_to_vrs_from_panorama(pano)

    # Address objects + rule refs per IP
    ip_contexts = {}  # ip -> {"objects":[], "refs":[], "starred_fw_ips": set()}
    for ip in IPS_TO_CHECK:
        objs = pano_addr_objs_for_ip(pano, ip)
        refs = []
        for o in objs:
            refs.extend(pano_rules_for_object(pano, o["name"]))
        dgs = dgs_for_rule_refs(refs)
        stars = starred_fw_ips_from_dgs(dgs)
        ip_contexts[ip] = {"objects": objs, "refs": refs, "starred_fw_ips": stars}

    pano.disconnect()

    # -------- Firewalls: one session per FW, process ALL IPs --------
    fw_results_all = {}  # fw_ip -> dict[ip] -> row
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {}
        for fw_ip, fw_name in FIREWALLS.items():
            pano_vrs = fw_to_vrs.get(fw_ip, [])
            futures[ex.submit(fw_worker_all_ips, fw_ip, fw_name, IPS_TO_CHECK, pano_vrs)] = (fw_ip, fw_name)
        for fut in as_completed(futures):
            fw_ip, _ = futures[fut]
            fw_results_all[fw_ip] = fut.result()

    # -------- Build stitched report --------
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
        lines.append(f"{'Firewall':<20} {'Mgmt IP':<15} {'VR':<20} {'Interface':<18} {'Zone':<24} {'Error':<0}")
        lines.append("-" * 108)

        for fw_ip, fw_name in sorted(FIREWALLS.items(), key=lambda kv: (kv[1], kv[0])):
            row = fw_results_all.get(fw_ip, {}).get(ip)
            if not row:
                row = {"fw": fw_name, "ip": fw_ip, "vr": "<n/a>", "iface": "<n/a>", "zone": "<n/a>", "err": "no data"}
            star = "★" if fw_ip in stars else " "
            fw_disp = f"{star} {row['fw']}"
            lines.append(f"{fw_disp:<20} {row['ip']:<15} {row['vr']:<20} {row['iface']:<18} {row['zone']:<24} {row['err']}")

        lines.append("")

    with open(results_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print("\n".join(lines))
    print(f"\nSaved stitched report: {os.path.abspath(LOG_DIR)}/{os.path.basename(results_path)}")
    print("Legend: ★ = firewall's DG has rules referencing the IP's address object(s)\n")


if __name__ == "__main__":
    main()
