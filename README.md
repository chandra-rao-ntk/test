#!/usr/bin/env python3
"""
Simple Palo Alto helper:
- Given an IP, find address object(s) on Panorama
- Find rules in Panorama that reference those objects
- On every firewall: find the zone for that IP via FIB -> interface -> zone
Fully read-only. Uses Netmiko (SSH).
"""

from getpass import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS =========
IP_TO_CHECK = "10.232.64.10"

PANORAMA_HOST = "10.212.240.150"   # FBAS21PANM001

# Firewalls: mgmt_ip : friendly_name
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

# VRs to try before discovering from config
VR_CANDIDATES = ["default", "VR-1", "vr1", "trust-vr", "untrust-vr"]
# =================================


def connect_panos(host, username, password, title=""):
    info = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
        "global_delay_factor": 1.0,
    }
    try:
        conn = ConnectHandler(**info)
        conn.send_command("set cli pager off", expect_string=r">|#")
        conn.send_command("set cli terminal width 500", expect_string=r">|#")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise RuntimeError(f"Failed to connect to {title or host}: {e}")


# ---------- PANORAMA HELPERS ----------

def pano_find_address_objects(conn, ip):
    """
    Returns a list of dicts:
      [{'scope':'shared' or 'device-group <name>', 'name':'ADDR_NAME', 'ip':'x.x.x.x'}]
    """
    conn.config_mode()
    out = conn.send_command(f"show | match {ip}", expect_string=r"\(config.*\)#")
    conn.exit_config_mode()

    results = []
    for line in out.splitlines():
        s = line.strip()
        # Example:
        # set shared address dv0621ssrs001_ASH ip-netmask 10.232.64.10
        # set device-group DGNAME address OBJNAME ip-netmask 10.232.64.10
        parts = s.split()
        if len(parts) >= 6 and parts[0] == "set" and parts[-2] == "ip-netmask" and parts[-1] == ip:
            if parts[1] == "shared" and parts[2] == "address":
                name = parts[3]
                results.append({"scope": "shared", "name": name, "ip": ip})
            elif parts[1] == "device-group":
                # set device-group <DG> address <NAME> ip-netmask <IP>
                if "address" in parts:
                    try:
                        dg = parts[2]
                        idx = parts.index("address")
                        name = parts[idx + 1]
                        results.append({"scope": f"device-group {dg}", "name": name, "ip": ip})
                    except Exception:
                        pass
    # de-dup by name
    seen = set()
    uniq = []
    for r in results:
        if r["name"] not in seen:
            seen.add(r["name"])
            uniq.append(r)
    return uniq


def pano_find_rules_for_object(conn, obj_name):
    """
    Return list of dicts describing rules referencing obj_name:
      [{'dg':..., 'where': 'pre-rulebase'|'post-rulebase'|'rulebase', 'rule':..., 'field': 'source'|'destination', 'line':<raw>}]
    """
    conn.config_mode()
    out = conn.send_command(f"show | match {obj_name}", expect_string=r"\(config.*\)#")
    conn.exit_config_mode()

    refs = []
    for line in out.splitlines():
        s = line.strip()
        if not s.startswith("set device-group "):
            continue
        if " security rules " not in s:
            continue
        parts = s.split()
        # Expect:
        # set device-group <DG> <pre-rulebase|post-rulebase|rulebase> security rules <RULE> <source|destination> ...
        try:
            dg = parts[2]
            where = parts[3]
            # find "rules" then rule name
            idx_rules = parts.index("rules")
            rule = parts[idx_rules + 1]
            field = "source" if " source " in f" {s} " else "destination"
            refs.append({"dg": dg, "where": where, "rule": rule, "field": field, "line": s})
        except Exception:
            continue

    # de-dup
    seen = set()
    uniq = []
    for r in refs:
        key = (r["dg"], r["where"], r["rule"], r["field"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


# ---------- FIREWALL HELPERS ----------

def discover_vrs(conn):
    """Scrape candidate VR names from running config (read-only)."""
    conn.config_mode()
    out = conn.send_command('show | match "set network virtual-router "', expect_string=r"\(config.*\)#")
    conn.exit_config_mode()
    vrs = []
    for line in out.splitlines():
        parts = line.strip().split()
        # set network virtual-router <VRNAME> ...
        if len(parts) >= 4 and parts[:3] == ["set", "network", "virtual-router"]:
            vrs.append(parts[3])
    return sorted(set(vrs))


def fib_lookup(conn, ip, vr_candidates=None):
    """
    Try VRs and return (interface, vr_used, raw_output) or (None, None, out).
    Prefer '[selected]' line; else take first interface line.
    """
    tried = []
    if vr_candidates is None:
        vr_candidates = VR_CANDIDATES[:]

    # Try provided candidates first
    for vr in vr_candidates:
        cmd = f"test routing fib-lookup virtual-router {vr} ip {ip}"
        out = conn.send_command(cmd)
        iface = _pick_interface_from_fib(out)
        if iface:
            return iface, vr, out
        tried.append(vr)

    # Fallback: discover VRs from config
    for vr in discover_vrs(conn):
        if vr in tried:
            continue
        cmd = f"test routing fib-lookup virtual-router {vr} ip {ip}"
        out = conn.send_command(cmd)
        iface = _pick_interface_from_fib(out)
        if iface:
            return iface, vr, out

    return None, None, out


def _pick_interface_from_fib(fib_output):
    """
    Choose the interface line with '[selected]' if present; otherwise first 'interface' seen.
    """
    selected_iface = None
    first_iface = None
    for raw in fib_output.splitlines():
        line = raw.strip()
        if "interface " in line:
            try:
                iface = line.split("interface", 1)[1].split()[0]
            except Exception:
                continue
            if first_iface is None:
                first_iface = iface
            if "[selected]" in line:
                selected_iface = iface
    return selected_iface or first_iface


def get_zone_for_interface(conn, interface):
    out = conn.send_command(f"show interface {interface}")
    # Output has a line like: "Zone: ENTERPRISE, virtual system: vsys1"
    for line in out.splitlines():
        if line.strip().startswith("Zone:"):
            # Zone: ENTERPRISE, virtual system: vsys1
            after = line.split("Zone:", 1)[1].strip()
            zone = after.split(",", 1)[0].strip()
            return zone
    return None


# ---------- MAIN FLOW ----------

def main():
    print(f"\n=== PAN Lookup (simple) for IP: {IP_TO_CHECK} ===\n")

    pano_user = input("Panorama username: ").strip()
    pano_pass = getpass("Panorama password: ")
    fw_user = input("Firewall username: ").strip()
    fw_pass = getpass("Firewall password: ")

    # Connect Panorama
    print(f"\n[*] Connecting to Panorama {PANORAMA_HOST} ...")
    pano = connect_panos(PANORAMA_HOST, pano_user, pano_pass, "Panorama")

    # Address objects
    print("[*] Searching address objects ...")
    addr_objs = pano_find_address_objects(pano, IP_TO_CHECK)
    if addr_objs:
        print("[+] Address object(s) for IP:")
        for obj in addr_objs:
            print(f"    - {obj['name']}  (scope: {obj['scope']})")
    else:
        print("[!] No address objects found for this IP on Panorama.")

    # Rules per object
    all_refs = []
    for obj in addr_objs:
        refs = pano_find_rules_for_object(pano, obj["name"])
        if refs:
            print(f"\n[+] Rules referencing '{obj['name']}':")
            for r in refs:
                print(f"    - DG={r['dg']}  {r['where']}  rule={r['rule']}  field={r['field']}")
            all_refs.extend(refs)
        else:
            print(f"\n[!] No rules reference '{obj['name']}'.")
    pano.disconnect()

    # Per-firewall zone checks
    print("\n[*] Checking zone on each firewall ...")
    results = []
    for host, fname in FIREWALLS.items():
        try:
            fw = connect_panos(host, fw_user, fw_pass, fname)
            iface, vr, _ = fib_lookup(fw, IP_TO_CHECK)
            zone = get_zone_for_interface(fw, iface) if iface else None
            fw.disconnect()
            results.append({
                "fw": fname, "ip": host,
                "vr": vr or "<unknown>",
                "iface": iface or "<not-found>",
                "zone": zone or "<not-found>",
            })
        except Exception as e:
            results.append({
                "fw": fname, "ip": host,
                "vr": "<error>", "iface": "<error>", "zone": f"<conn failed: {e}>",
            })

    # Report
    print("\n=== SUMMARY ===")
    if addr_objs:
        print("\nAddress object(s):")
        for o in addr_objs:
            print(f"  - {o['name']}  (scope: {o['scope']})")

    if all_refs:
        print("\nRules that reference the object(s):")
        for r in all_refs:
            print(f"  - DG={r['dg']:<14} {r['where']:<12} rule={r['rule']:<40} field={r['field']}")
    else:
        print("\nRules that reference the object(s): <none found>")

    print("\nPer-firewall routing & zone:")
    print(f"{'Firewall':<18} {'Mgmt IP':<15} {'VR':<16} {'Interface':<18} {'Zone':<24}")
    print("-" * 96)
    for r in results:
        print(f"{r['fw']:<18} {r['ip']:<15} {r['vr']:<16} {r['iface']:<18} {r['zone']:<24}")

    print("\nDone.\n")


if __name__ == "__main__":
    main()
