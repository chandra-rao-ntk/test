#!/usr/bin/env python3
"""
Palo Alto Networks helper: Given an IP, show:
- Address object name(s) in Panorama
- All Panorama rules (device-group + rulebase + rule) that reference that object
- For each firewall, the egress interface/zone that IP belongs to (routing FIB -> interface -> zone)

Requirements:
    pip install netmiko

Usage:
    python palo_find_zone_and_rules.py
    (script will prompt for creds)

Notes:
- Panorama + firewalls are treated as PAN-OS SSH targets via Netmiko "paloalto_panos".
- FIB lookup tries VR "default" first, then falls back to any VR names discovered from running config.
- If multiple routes are present, we pick the line marked [selected].
"""

import re
import sys
import time
from getpass import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# --------- USER INPUTS ----------
IP_TO_CHECK = "10.232.64.10"

PANORAMA = {
    "device_type": "paloalto_panos",
    "host": "10.212.240.150",   # FBAS21PANM001
    "username": None,           # prompted
    "password": None,           # prompted
    "fast_cli": False,
    "global_delay_factor": 1.0,
}

# Firewalls: mgmt_ip -> friendly_name
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
# --------------------------------

SET_PAGER_OFF = "set cli pager off"
SET_WIDTH     = "set cli terminal width 500"

ADDR_LINE_PAT = re.compile(
    r"""^set\s+            # starts with 'set'
        (?P$scope>shared|device-group\s+\S+)\s+
        address\s+(?P<name>\S+)\s+
        ip-netmask\s+(?P<ip>\S+)""",
    re.IGNORECASE | re.VERBOSE,
)

# Example matches for rules (pre/post/local) referencing the object
# e.g.:
# set device-group FBAS21NPFW pre-rulebase security rules USERS_TO_DUO source dv0621...
# set device-group FBAS21PRFW pre-rulebase security rules DBA_TEAM_TO_SQL_SSRS destination [ ... OBJECT ... ]
RULE_LINE_PAT = re.compile(
    r"""^set\s+device-group\s+(?P<dg>\S+)\s+
        (?P<where>pre-rulebase|post-rulebase|rulebase)\s+
        security\s+rules\s+(?P<rule>\S+)\s+
        (?P<dir>source|destination)\b.*$""",
    re.IGNORECASE | re.VERBOSE,
)

VR_NAME_PAT = re.compile(r'^set\s+network\s+virtual-router\s+(\S+)', re.IGNORECASE)

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
        conn.send_command(SET_PAGER_OFF, expect_string=r">|#")
        conn.send_command(SET_WIDTH, expect_string=r">|#")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise RuntimeError(f"Failed to connect to {title or host}: {e}")

def panorama_find_address_objects(conn, ip):
    """
    Enter configure mode and 'show | match <ip>' to find address objects
    Returns a list of dicts: [{scope, name, ip}]
    """
    conn.config_mode()
    out = conn.send_command(f"show | match {ip}", expect_string=r"\(config.*\)#")
    conn.exit_config_mode()
    objects = []
    for line in out.splitlines():
        line = line.strip()
        m = ADDR_LINE_PAT.match(line)
        if m and m.group("ip") == ip:
            objects.append({
                "scope": m.group("scope"),
                "name": m.group("name"),
                "ip": m.group("ip"),
            })
    return objects

def panorama_find_rules_for_object(conn, obj_name):
    """
    Enter configure mode and 'show | match <obj_name>' to find rules referencing it
    Returns list of dicts: [{dg, where, rule, dir, line}]
    """
    conn.config_mode()
    out = conn.send_command(f"show | match {obj_name}", expect_string=r"\(config.*\)#")
    conn.exit_config_mode()
    refs = []
    for line in out.splitlines():
        if "security rules" not in line:
            continue
        m = RULE_LINE_PAT.match(line.strip())
        if m:
            refs.append({
                "dg": m.group("dg"),
                "where": m.group("where"),
                "rule": m.group("rule"),
                "dir": m.group("dir"),
                "line": line.strip(),
            })
    # de-dup
    uniq = []
    seen = set()
    for r in refs:
        key = (r["dg"], r["where"], r["rule"], r["dir"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq

def discover_vrs(conn):
    """Get VR names by scraping running config 'set network virtual-router <name>'."""
    conn.config_mode()
    out = conn.send_command('show | match "set network virtual-router "', expect_string=r"\(config.*\)#")
    conn.exit_config_mode()
    vrs = sorted(set(VR_NAME_PAT.findall(out)))
    return vrs

def fib_lookup(conn, ip, vr_candidates=None):
    """
    Returns (interface, vr_used, raw_output) or (None, None, raw_output_if_any)
    Tries candidates; if none succeed, discovers VRs from config and tries those.
    """
    tried = []
    out = ""
    if vr_candidates is None:
        vr_candidates = ["default", "VR-1", "vr1", "trust-vr", "untrust-vr"]

    for vr in vr_candidates:
        cmd = f"test routing fib-lookup virtual-router {vr} ip {ip}"
        out = conn.send_command(cmd)
        tried.append(vr)
        if "interface" in out:
            iface = _parse_selected_interface(out)
            if iface:
                return iface, vr, out

    # fallback: discover VRs from config
    vrs = discover_vrs(conn)
    for vr in vrs:
        if vr in tried:
            continue
        cmd = f"test routing fib-lookup virtual-router {vr} ip {ip}"
        out = conn.send_command(cmd)
        if "interface" in out:
            iface = _parse_selected_interface(out)
            if iface:
                return iface, vr, out

    return None, None, out

def _parse_selected_interface(fib_output):
    """
    Pick interface from the [selected] line if present; otherwise the first 'interface <x>'
    """
    iface = None
    for line in fib_output.splitlines():
        if "interface " in line:
            m = re.search(r"interface\s+(\S+)", line)
            if m:
                iface = m.group(1)
            if "[selected]" in line:
                return iface
    return iface

def get_zone_for_interface(conn, interface):
    out = conn.send_command(f"show interface {interface}")
    m = re.search(r"Zone:\s*([A-Za-z0-9_\-]+)", out)
    return m.group(1) if m else None

def run():
    print(f"\n=== PAN Helper for IP: {IP_TO_CHECK} ===\n")

    # --- creds
    print("[*] Enter Panorama credentials")
    PANORAMA["username"] = input("Panorama username: ").strip()
    PANORAMA["password"] = getpass("Panorama password: ")

    fw_username = input("\nFirewall username: ").strip()
    fw_password = getpass("Firewall password: ")

    # --- Panorama lookup
    print(f"\n[*] Connecting to Panorama {PANORAMA['host']} ...")
    pano = connect_panos(PANORAMA["host"], PANORAMA["username"], PANORAMA["password"], "Panorama")

    try:
        print("[*] Searching for address objects on Panorama ...")
        addr_objs = panorama_find_address_objects(pano, IP_TO_CHECK)
        if not addr_objs:
            print(f"[!] No address objects found for {IP_TO_CHECK} on Panorama.")
        else:
            print("[+] Address object(s) for IP:")
            for o in addr_objs:
                print(f"    - {o['name']}  (scope: {o['scope']})")

        # gather rules per object
        all_refs = []
        for o in addr_objs:
            refs = panorama_find_rules_for_object(pano, o["name"])
            if refs:
                print(f"\n[+] Rules referencing '{o['name']}':")
                for r in refs:
                    print(f"    - DG={r['dg']}  {r['where']}  rule={r['rule']}  field={r['dir']}")
                all_refs.extend(refs)
            else:
                print(f"\n[!] No rules reference '{o['name']}'.")

    finally:
        pano.disconnect()

    # --- Firewall zone checks
    print("\n[*] Checking zone on each firewall (FIB → interface → zone) ...")
    rows = []
    for host, name in FIREWALLS.items():
        info = {
            "device_type": "paloalto_panos",
            "host": host,
            "username": fw_username,
            "password": fw_password,
            "fast_cli": False,
            "global_delay_factor": 1.0,
        }
        try:
            conn = ConnectHandler(**info)
            conn.send_command(SET_PAGER_OFF, expect_string=r">|#")
            conn.send_command(SET_WIDTH, expect_string=r">|#")

            iface, vr, fib_out = fib_lookup(conn, IP_TO_CHECK)
            if iface:
                zone = get_zone_for_interface(conn, iface)
            else:
                zone = None

            rows.append({
                "fw_name": name,
                "fw_ip": host,
                "vr": vr or "<unknown>",
                "interface": iface or "<not-found>",
                "zone": zone or "<not-found>",
            })

        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            rows.append({
                "fw_name": name,
                "fw_ip": host,
                "vr": "<error>",
                "interface": "<error>",
                "zone": f"<conn failed: {e}>",
            })
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass

    # --- Report
    print("\n=== RESULTS ===")
    # Address objects summary
    if addr_objs:
        print("\nAddress objects for IP:")
        for o in addr_objs:
            print(f"  - {o['name']}  (scope: {o['scope']})")
    else:
        print("\nAddress objects for IP: <none>")

    # Rules summary
    # de-dup across objects in case same object repeated
    # Already deduped per object
    if 'all_refs' in locals() and all_refs:
        print("\nRules referencing the address object(s):")
        for r in all_refs:
            print(f"  - DG={r['dg']:<14} {r['where']:<12} rule={r['rule']:<40} field={r['dir']}")
    else:
        print("\nRules referencing the address object(s): <none found>")

    # Per-firewall zone table
    print("\nPer-firewall routing & zone:")
    print(f"{'Firewall':<18} {'Mgmt IP':<15} {'VR':<16} {'Interface':<16} {'Zone':<24}")
    print("-" * 92)
    for row in rows:
        print(f"{row['fw_name']:<18} {row['fw_ip']:<15} {row['vr']:<16} {row['interface']:<16} {row['zone']:<24}")

    print("\nDone.\n")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)
