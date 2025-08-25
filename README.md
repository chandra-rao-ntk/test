#!/usr/bin/env python3
"""
Given an IP:
  1) Panorama (SSH, config mode, set-format):
       - show | match <IP>                  -> address object name(s) (can be multiple)
       - show | match <OBJECT_NAME>         -> all security rules referencing it (DG + pre/post/local)
  2) Firewalls (SSH):
       - test routing fib-lookup virtual-router <vr> ip <IP> -> egress interface
       - show interface <if> -> Zone
Read-only; no commits. Session-only CLI tweaks.
Requires: pip install netmiko
"""

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS (same creds for Panorama & FWs) =========
USERNAME = "admin"
PASSWORD = "your-password-here"

IP_TO_CHECK = "10.232.64.10"

PANORAMA_HOST = "10.232.240.150"  # << updated as requested

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

# Try these VR names first (script will auto-discover others if needed)
VR_CANDIDATES = ["default", "VR-1", "vr1", "trust-vr", "untrust-vr"]
# ================================================================


def connect_panos(host, title=""):
    info = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": USERNAME,
        "password": PASSWORD,
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


# -------------------- PANORAMA LOOKUPS --------------------

def pano_get_address_objects_for_ip(conn, ip):
    """
    Panorama config mode, 'set' format, then 'show | match <ip>'.
    Accepts:
        set shared address <NAME> ip-netmask <IP>
        set device-group <DG> address <NAME> ip-netmask <IP>
    Returns list of {'name': NAME, 'scope': 'shared' or 'device-group <DG>'}
    """
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
    return objs


def pano_get_rules_for_object(conn, obj_name):
    """
    Panorama config mode, 'set' format, 'show | match <obj_name>'.
    Keep only security rule lines, de-dup.
    Returns [{'obj':obj_name,'dg':..., 'where': pre-rulebase|post-rulebase|rulebase, 'rule':..., 'field':'source'|'destination'}]
    """
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
            where  = parts[3]  # pre-rulebase | post-rulebase | rulebase
            rule   = parts[parts.index("rules")+1]
            field  = "source" if " source " in f" {s} " else ("destination" if " destination " in f" {s} " else "unknown")
            key    = (obj_name, dg, where, rule, field)
            if key not in seen:
                seen.add(key)
                refs.append({"obj": obj_name, "dg": dg, "where": where, "rule": rule, "field": field})
        except Exception:
            continue
    return refs


# -------------------- FIREWALL LOOKUPS --------------------

def discover_vrs(conn):
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


def fib_lookup(conn, ip):
    """Return (interface, vr_used). Try VR_CANDIDATES then discovered VRs. Prefer '[selected]'."""
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


# -------------------- MAIN --------------------

def main():
    print(f"\n=== PAN Lookup for IP: {IP_TO_CHECK} ===\n")

    # Panorama
    print(f"[*] Connecting to Panorama {PANORAMA_HOST} ...")
    pano = connect_panos(PANORAMA_HOST, "Panorama")

    print("[*] Searching address objects on Panorama (show | match <IP>) ...")
    addr_objs = pano_get_address_objects_for_ip(pano, IP_TO_CHECK)
    if addr_objs:
        print("[+] Address object(s) for IP:")
        for o in addr_objs:
            print(f"    - {o['name']}  ({o['scope']})")
    else:
        print("[!] No address objects found for this IP on Panorama.")

    # For each object, find rules that reference it (handles MULTIPLE objects)
    all_refs = []
    for o in addr_objs:
        refs = pano_get_rules_for_object(pano, o["name"])
        if refs:
            print(f"\n[+] Rules referencing '{o['name']}':")
            for r in refs:
                print(f"    - DG={r['dg']}  {r['where']}  rule={r['rule']}  field={r['field']}")
            all_refs.extend(refs)
        else:
            print(f"\n[!] No rules reference '{o['name']}'.")
    pano.disconnect()

    # Firewalls
    print("\n[*] Checking routing/zone on each firewall ...")
    rows = []
    for host, name in FIREWALLS.items():
        try:
            fw = connect_panos(host, name)
            iface, vr = fib_lookup(fw, IP_TO_CHECK)
            zone = get_zone_for_interface(fw, iface)
            fw.disconnect()
            rows.append({"fw": name, "ip": host, "vr": vr or "<unknown>",
                         "iface": iface or "<not-found>", "zone": zone or "<not-found>"})
        except Exception as e:
            rows.append({"fw": name, "ip": host, "vr": "<error>", "iface": "<error>", "zone": f"<conn failed: {e}>"})

    # Report
    print("\n=== SUMMARY ===")
    if addr_objs:
        print("\nAddress object(s):")
        for o in addr_objs:
            print(f"  - {o['name']}  ({o['scope']})")
    else:
        print("\nAddress object(s): <none>")

    if all_refs:
        print("\nRules referencing the object name(s):")
        seen = set()
        for r in all_refs:
            key = (r['obj'], r['dg'], r['where'], r['rule'], r['field'])
            if key in seen:
                continue
            seen.add(key)
            print(f"  - OBJ={r['obj']:<22} DG={r['dg']:<14} {r['where']:<12} rule={r['rule']:<40} field={r['field']}")
    else:
        print("\nRules referencing the object name(s): <none>")

    print("\nPer-firewall routing & zone:")
    print(f"{'Firewall':<18} {'Mgmt IP':<15} {'VR':<16} {'Interface':<18} {'Zone':<24}")
    print("-" * 96)
    for r in rows:
        print(f"{r['fw']:<18} {r['ip']:<15} {r['vr']:<16} {r['iface']:<18} {r['zone']:<24}")
    print("\nDone.\n")


if __name__ == "__main__":
    main()
