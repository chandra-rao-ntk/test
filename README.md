#!/usr/bin/env python3
# Read-only PAN workflow (multi-IP, multi-VR, aligned, always list all FWs)
# - Panorama: objects+rules per IP, discover VRs per template (supports [ INT_VR EXT_VR ])
# - Firewalls: one session per FW; run FIB for ALL IPs across ALL VRs; cache interface->zone
# - Shows ALL FWs; star (★) rows whose DG has rules for the IP
# - Per-session logs + stitched report in ./logs/

import os, re, logging, datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS =========
USERNAME = "admin"
PASSWORD  = "REPLACE_ME"

IPS_TO_CHECK = [
    "10.232.64.10",
    "10.212.64.10",
    "10.232.68.162",
    "10.212.68.162",
]

PANORAMA_HOST = "10.232.240.150"

# Firewalls (mgmt_ip -> friendly name)
FIREWALLS = {
    "10.232.240.151": "FBAS21INFW001",
    "10.232.240.161": "FBAS21NPFW001",
    "10.232.240.155": "FBAS21PAFW001",
    "10.232.240.159": "FBAS21PRFW001",
    "10.232.240.153": "FBAS21SSFW001",
    "10.232.240.157": "FBAS21VPFW001",
    "10.212.240.152": "FBCH03INFW002",  # you added INFW002 here
    "10.212.240.161": "FBCH03NPFW001",
    "10.212.240.155": "FBCH03PAFW001",
    "10.212.240.159": "FBCH03PRFW001",
    "10.212.240.153": "FBCH03SSFW001",
    # "10.212.240.157": "FBCH03VPFW001",
}

# OPTIONAL Panorama template overrides (mgmt_ip -> template name)
TEMPLATE_OVERRIDE = {
    # "10.232.240.151": "FBAS21INFW_Template",
}

# Force certain FWs to always try these VRs (unioned with Panorama discovery; forced first)
FORCE_FW_VRS = {
    "10.232.240.157": ["INT_VR", "EXT_VR"],  # FBAS21VPFW001
    # "10.212.240.157": ["INT_VR", "EXT_VR"],  # FBCH03VPFW001
}

# Device-group -> firewall mgmt IPs (for ★ marking only)
DG_TO_FIREWALLS = {
    "FBAS21INFW": ["10.232.240.151"],
    "FBAS21NPFW": ["10.232.240.161"],
    "FBAS21PAFW": ["10.232.240.155"],
    "FBAS21PRFW": ["10.232.240.159"],
    "FBAS21SSFW": ["10.232.240.153"],
    "FBAS21VPFW": ["10.232.240.157"],
    "FBCH03INFW": ["10.212.240.151"],   # note: your list now has 10.212.240.152 for INFW002
    "FBCH03NPFW": ["10.212.240.161"],
    "FBCH03PAFW": ["10.212.240.155"],
    "FBCH03PRFW": ["10.212.240.159"],
    "FBCH03SSFW": ["10.212.240.153"],
    # "FBCH03VPFW": ["10.212.240.157"],
}

MAX_WORKERS = 10
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
    Parse lines such as:
      set template <T> config vsys vsys1 import network virtual-router default
      set template <T> config vsys vsys1 import network virtual-router [ INT_VR EXT_VR ]
    → {template: [vr,...]}
    """
    conn.config_mode()
    out = conn.send_command(
        'show | match "set template " | match " vsys vsys1 import network virtual-router "',
        expect_string=r"#", read_timeout=90,
    )
    conn.exit_config_mode()
    mapping = {}
    for line in out.splitlines():
        s = line.strip()
        if not s.startswith("set template ") or " vsys vsys1 import network virtual-router " not in s:
            continue
        parts = s.split()
        tmpl = parts[2]
        tail = s.split("virtual-router", 1)[1].strip()
        if tail.startswith("["):
            inside = tail.strip("[]").strip()
            vrs = [tok.strip(",") for tok in inside.split() if tok not in ("[", "]")]
        else:
            vrs = [tail.split()[0].strip(",")]
        mapping.setdefault(tmpl, [])
        for vr in vrs:
            if vr and vr not in mapping[tmpl]:
                mapping[tmpl].append(vr)
    if not mapping:
        _write_log("pano_template_vrs_raw.txt", out)
    return mapping

def heuristic_template_name(fw_name: str) -> str:
    base = re.sub(r"\d+$", "", fw_name)
    return f"{base}_Template"

def build_fw_to_vrs_from_panorama(conn):
    tmpl_vrs = pano_template_vrs(conn)
    fw_to_vrs = {}
    for mgmt_ip, fw_name in FIREWALLS.items():
        tmpl = TEMPLATE_OVERRIDE.get(mgmt_ip, heuristic_template_name(fw_name))
        vrs = tmpl_vrs.get(tmpl, [])
        forced = FORCE_FW_VRS.get(mgmt_ip, [])
        vrs = forced + [vr for vr in vrs if vr not in forced]
        fw_to_vrs[mgmt_ip] = vrs
    return fw_to_vrs

# ---------- Firewall ops ----------
def discover_vrs_on_fw(conn):
    vrs = set()
    out1 = conn.send_command("show routing summary", read_timeout=30)
    for line in out1.splitlines():
        m = re.search(r"\bvirtual[-\s]?router\s+([A-Za-z0-9._-]+)", line, re.IGNORECASE)
        if m: vrs.add(m.group(1))
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

def fib_lookup_multi_all_vrs(conn, ips, vrs):
    """
    Try every VR for each IP and return results including non-matches (iface=None).
    Returns: { ip: [ (vr, iface_or_None) , ... ] }
    """
    if not vrs:
        vrs = discover_vrs_on_fw(conn)
    results = {ip: [] for ip in ips}
    for ip in ips:
        seen = set()
        for vr in vrs:
            iface = fib_try(conn, vr, ip)
            key = (vr, iface or "<none>")
            if key in seen:
                continue
            seen.add(key)
            results[ip].append((vr, iface))
    return results

def get_zone_for_interface(conn, fw_host: str, interface: str):
    if not interface:
        return None
    cmd1 = f"show interface {interface} | match Zone"
    out1 = conn.send_command(cmd1, read_timeout=30)
    for line in out1.splitlines():
        s = line.strip()
        if s.lower().startswith("zone"):
            return s.split(":", 1)[-1].strip().split(",", 1)[0].strip()
    cmd2 = f"show interface {interface} | match zone"
    out2 = conn.send_command(cmd2, read_timeout=30)
    for line in out2.splitlines():
        s = line.strip()
        if s.lower().startswith("zone"):
            return s.split(":", 1)[-1].strip().split(",", 1)[0].strip()
    conn.config_mode()
    cmd3 = f"show | match zone | match {interface}"
    out3 = conn.send_command(cmd3, expect_string=r"#", read_timeout=60)
    conn.exit_config_mode()
    for s in out3.splitlines():
        s = s.strip()
        if s.startswith("set ") and " zone " in s and interface in s:
            try:
                return s.split(" zone ", 1)[1].split()[0]
            except Exception:
                pass
    _write_log(f"{fw_host}_zone_debug_{interface}.txt",
               f"$ {cmd1}\n{out1}\n\n$ {cmd2}\n{out2}\n\n$ {cmd3}\n{out3}\n")
    return None

def fw_worker_all_ips(fw_ip, fw_name, ip_list, pano_vrs_for_fw):
    """
    One connection per FW:
      - Use Panorama VR list (fallback to local discovery)
      - Run FIB for ALL IPs across ALL VRs
      - Return list of rows per IP (one row per VR, even if no route)
    """
    out = {}
    try:
        fw = connect_panos(fw_ip, fw_name)
        vr_pairs = fib_lookup_multi_all_vrs(fw, ip_list, pano_vrs_for_fw)  # {ip: [(vr, iface|None), ...]}
        zone_cache = {}
        for ip in ip_list:
            rows = []
            for vr, iface in vr_pairs.get(ip, []):
                if iface:
                    if iface in zone_cache:
                        zone = zone_cache[iface]
                    else:
                        zone = get_zone_for_interface(fw, fw_ip, iface) or "<not-found>"
                        zone_cache[iface] = zone
                    rows.append({"fw": fw_name, "ip": fw_ip, "vr": vr,
                                 "iface": iface, "zone": zone, "err": ""})
                else:
                    rows.append({"fw": fw_name, "ip": fw_ip, "vr": vr,
                                 "iface": "<not-found>", "zone": "<not-found>", "err": ""})
            if not rows:
                rows.append({"fw": fw_name, "ip": fw_ip, "vr": "<unknown>",
                             "iface": "<not-found>", "zone": "<not-found>", "err": ""})
            out[ip] = rows
        fw.disconnect()
        return out
    except Exception as e:
        # Hard failure: return placeholder rows so caller always has an entry
        for ip in ip_list:
            out[ip] = [{"fw": fw_name, "ip": fw_ip, "vr": "<error>",
                        "iface": "<error>", "zone": "<error>", "err": str(e)}]
        return out

# ---------- stars, table, report ----------
def dgs_for_rule_refs(rule_refs): return {r["dg"] for r in rule_refs}

def starred_fw_ips_from_dgs(rule_dgs):
    starred = set()
    for dg in rule_dgs:
        starred.update(DG_TO_FIREWALLS.get(dg, []))
    return starred

def format_table(rows, starred_ips):
    # Prepare display rows with star prefix
    disp = []
    for r in rows:
        star = "★" if r["ip"] in starred_ips else " "
        disp.append({
            "fw": f"{star} {r['fw']}",
            "ip": r["ip"],
            "vr": r["vr"],
            "iface": r["iface"],
            "zone": r["zone"],
            "err": r.get("err", ""),
        })
    # Column widths
    fw_w = max(20, max(len(x["fw"]) for x in disp))
    ip_w = max(15, max(len(x["ip"]) for x in disp))
    vr_w = max(22, max(len(x["vr"]) for x in disp))
    if_w = max(14, max(len(x["iface"]) for x in disp))
    zn_w = max(14, max(len(x["zone"]) for x in disp))
    header = f"{'Firewall':<{fw_w}} {'Mgmt IP':<{ip_w}} {'VR':<{vr_w}} {'Interface':<{if_w}} {'Zone':<{zn_w}} Error"
    sep    = "-" * (fw_w + ip_w + vr_w + if_w + zn_w + len(" Error") + 4)
    lines  = [header, sep]
    for x in disp:
        lines.append(f"{x['fw']:<{fw_w}} {x['ip']:<{ip_w}} {x['vr']:<{vr_w}} {x['iface']:<{if_w}} {x['zone']:<{zn_w}} {x['err']}")
    return lines

def main():
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = os.path.join(LOG_DIR, f"results_{ts}.txt")

    print(f"\n=== PAN Multi-IP Lookup (multi-VR, always list all FWs) ===")
    print(f"Panorama: {PANORAMA_HOST}")
    print(f"IPs: {', '.join(IPS_TO_CHECK)}")
    print(f"Logs dir: {os.path.abspath(LOG_DIR)}\n")

    # Panorama once
    pano = connect_panos(PANORAMA_HOST, "Panorama")
    fw_to_vrs = build_fw_to_vrs_from_panorama(pano)

    ip_ctx = {}
    for ip in IPS_TO_CHECK:
        objs = pano_addr_objs_for_ip(pano, ip)
        refs = []
        for o in objs:
            refs.extend(pano_rules_for_object(pano, o["name"]))
        stars = starred_fw_ips_from_dgs(dgs_for_rule_refs(refs))
        ip_ctx[ip] = {"objs": objs, "refs": refs, "stars": stars}
    pano.disconnect()

    # Firewalls once each (robust: never drop a firewall if a future raises)
    fw_results_all = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(fw_worker_all_ips, fw_ip, fw_name, IPS_TO_CHECK, fw_to_vrs.get(fw_ip, [])): (fw_ip, fw_name)
                   for fw_ip, fw_name in FIREWALLS.items()}
        for fut in as_completed(futures):
            fw_ip, fw_name = futures[fut]
            try:
                fw_results_all[fw_ip] = fut.result()
            except Exception as e:
                # Absolute fallback if something slipped past the worker try/except
                fw_results_all[fw_ip] = {ip: [{"fw": fw_name, "ip": fw_ip, "vr": "<error>",
                                               "iface": "<error>", "zone": "<error>", "err": str(e)}]
                                         for ip in IPS_TO_CHECK}

    # Ensure we have an entry for *every* firewall even if nothing came back
    for fw_ip, fw_name in FIREWALLS.items():
        if fw_ip not in fw_results_all:
            fw_results_all[fw_ip] = {ip: [{"fw": fw_name, "ip": fw_ip, "vr": "<n/a>",
                                           "iface": "<n/a>", "zone": "<n/a>", "err": "no data"}]
                                     for ip in IPS_TO_CHECK}

    # Build stitched report
    out_lines = []
    for ip in IPS_TO_CHECK:
        ctx = ip_ctx[ip]
        out_lines.append(f"===== IP: {ip} =====")
        if ctx["objs"]:
            out_lines.append("Address object(s):")
            for o in ctx["objs"]:
                out_lines.append(f"  - {o['name']} ({o['scope']})")
        else:
            out_lines.append("Address object(s): <none found>")

        if ctx["refs"]:
            out_lines.append("Rules referencing the object name(s):")
            seen = set()
            for r in ctx["refs"]:
                key = (r['obj'], r['dg'], r['where'], r['rule'], r['field'])
                if key in seen: continue
                seen.add(key)
                out_lines.append(f"  - OBJ={r['obj']:<24} DG={r['dg']:<14} {r['where']:<12} rule={r['rule']:<40} field={r['field']}")
        else:
            out_lines.append("Rules referencing the object name(s): <none>")

        # Flatten rows for this IP (guaranteed at least one row per FW)
        flat_rows = []
        for fw_ip, fw_name in FIREWALLS.items():
            rows = fw_results_all.get(fw_ip, {}).get(ip, [])
            if not rows:
                rows = [{"fw": fw_name, "ip": fw_ip, "vr": "<n/a>", "iface": "<n/a>", "zone": "<n/a>", "err": "no data"}]
            flat_rows.extend(rows)

        out_lines.append("Per-firewall routing & zone (ALL FWs; ★ = DG has matching rules; one line per VR):")
        out_lines.extend(format_table(flat_rows, ctx["stars"]))
        out_lines.append("")

    with open(results_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    print("\n".join(out_lines))
    print(f"\nSaved stitched report: {os.path.abspath(LOG_DIR)}/{os.path.basename(results_path)}")
    print("Legend: ★ = firewall's DG has rules referencing the IP's address object(s)\n")

if __name__ == "__main__":
    main()
