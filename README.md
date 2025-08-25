#!/usr/bin/env python3
"""
Given an IP:
  1) On Panorama: find address object name(s) with that IP
  2) On Panorama: find every security rule (DG + pre/post/local) that references those objects
  3) On each firewall: FIB lookup -> interface -> zone for that IP
Print a single consolidated report.

Read-only. No config changes/commits. Session-only CLI tweaks (pager/width/output-format).

Requires:  pip install netmiko
"""

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ========= USER SETTINGS (same creds for Panorama + all firewalls) =========
USERNAME = "admin"
PASSWORD = "your-password-here"

IP_TO_CHECK = "10.232.64.10"

PANORAMA_HOST = "10.212.240.150"  # FBAS21PANM001

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

# Try these VR names first; script will auto-discover others if needed
VR_CANDIDATES = ["default", "VR-1", "vr1", "trust-vr", "untrust-vr"]
# ==========================================================================


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
        # Session-only tweaks
        conn.send_command("set cli pager off", expect_string=r">|#")
        conn.send_command("set cli terminal width 500", expect_string=r">|#")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise RuntimeError(f"Failed to connect to {title or host}: {e}")


# -------------------- PANORAMA LOOKUPS --------------------

def pano_find_address_objects(conn, ip):
    """
    Return [{'scope': 'shared' or 'device-group <dg>', 'name': 'OBJ', 'ip': ip}, ...]
    Uses config mode with 'set' formatting so we can parse simple 'set ...' lines.
    """
    conn.config_mode()                      # prompt ends with '#'
    conn.send_command("set cli config-output-format set", expect_string=r"#")

    out = conn.send_command(f"show | match {ip}", expect_string=r"#", read_timeout=60)
    conn.exit_config_mode()

    results = []
    for line in out.splitlines():
        s = line.strip()
        parts = s.split()
        # expected forms:
        # set shared address <NAME> ip-netmask <IP>
        # set device-group <DG> address <NAME> ip-netmask <IP>
        if len(parts) >= 6 and parts[0] == "set" and parts[-2] == "ip-netmask" and parts[-1] == ip:
            if parts[1] == "shared" and parts[2] == "address":
                results.append({"scope": "shared", "name": parts[3], "ip": ip})
            elif parts[1] == "device-group":
                dg = parts[2]
                # find "address" then take next token as name
                if "address" in parts:
                    idx = parts.index("address")
                    if idx + 1 < len(parts):
                        results.append({"scope": f"device-group {dg}", "name": parts[idx + 1], "ip": ip})

    # de-dup by name
    seen, uniq = set(), []
    for r in results:
        if r["name"] not in seen:
            seen.add(r["name"])
            uniq.append(r)
    return uniq


def pano_find_rules_for_object(conn, obj_name):
    """
    Return [{dg, where(pre/post/rulebase), rule, field(source/destination), line}, ...]
    """
    conn.config_mode()
    conn.send_command("set cli config-output-format set", expect_string=r"#")
    out = conn.send_command(f"show | match {obj_name}", expect_string=r"#", read_timeout=60)
    conn.exit_config_mode()

    refs = []
    for line in out.splitlines():
        s = line.strip()
        # we only care about lines that are security rules
        if not s.startswith("set device-group ") or " security rules " not in s:
            continue
        parts = s.split()
        try:
            dg = parts[2]
            where = parts[3]  # pre-rulebase | post-rulebase | rulebase
            idx_rules = parts.index("rules")
            rule = parts[idx_rules + 1]
            field = "source" if " source " in f" {s} " else ("destination" if " destination " in f" {s} " else "unknown")
            refs.append({"dg": dg, "where": where, "rule": rule, "field": field, "line": s})
        except Exception:
            continue

    # de-dup
    seen, uniq = set(), []
    for r in refs:
        key = (r["dg"], r["where"], r["rule"], r["field"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


# -------------------- FIREWALL LOOKUPS --------------------

def discover_vrs(conn):
    """Scrape VR names from running config (read-only)."""
    conn.config_mode()
    conn.send_command("set cli config-output-format set", expect_string=r"#")
    out = conn.send_command('show | match "set network virtual-router "', expect_string=r"#", read_timeout=60)
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
    Try VRs and return (interface, vr_used). Prefer the '[selected]' line.
    """
    if vr_candidates is None:
        vr_candidates = VR_CANDIDATES[:]

    tried = set()
    # First try provided candidates
    for vr in vr_candidates:
        iface = _fib_try_vr(conn, vr, ip)
        tried.add(vr)
        if iface:
            return iface, vr

    # Then auto-discover VRs
    for vr in discover_vrs(conn):
        if vr in tried:
            continue
        iface = _fib_try_vr(conn, vr, ip)
        if iface:
            return iface, vr

    return None, None


def _fib_try_vr(conn, vr, ip):
    out = conn.send_command(f"test routing fib-lookup virtual-router {vr} ip {ip}", read_timeout=45)
    selected, first = None, None
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
            # "Zone: ENTERPRISE, virtual system: vsys1"
            after = line.split("Zone:", 1)[1].strip()
            return after.split(",", 1)[0].strip()
    return None


# -------------------- MAIN --------------------

def main():
    print(f"\n=== PAN Lookup for IP: {IP_TO_CHECK} ===\n")

    # Panorama
    print(f"[*] Connecting to Panorama {PANORAMA_HOST} ...")
    pano = connect_panos(PANORAMA_HOST, "Panorama")

    print("[*] Searching address objects on Panorama ...")
    addr_objs = pano_find_address_objects(pano, IP_TO_CHECK)
    if addr_objs:
        print("[+] Address object(s):")
        for o in addr_objs:
            print(f"    - {o['name']}  ({o['scope']})")
    else:
        print("[!] No address objects found for this IP on Panorama.")

    all_refs = []
    for o in addr_objs:
        refs = pano_find_rules_for_object(pano, o["name"])
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
            rows.append({
                "fw": name, "ip": host,
                "vr": vr or "<unknown>",
                "iface": iface or "<not-found>",
                "zone": zone or "<not-found>",
            })
        except Exception as e:
            rows.append({
                "fw": name, "ip": host,
                "vr": "<error>", "iface": "<error>", "zone": f"<conn failed: {e}>",
            })

    # Report
    print("\n=== SUMMARY ===")
    if addr_objs:
        print("\nAddress object(s):")
        for o in addr_objs:
            print(f"  - {o['name']}  ({o['scope']})")
    else:
        print("\nAddress object(s): <none>")

    if all_refs:
        print("\nRules that reference the object(s):")
        for r in all_refs:
            print(f"  - DG={r['dg']:<14} {r['where']:<12} rule={r['rule']:<40} field={r['field']}")
    else:
        print("\nRules that reference the object(s): <none>")

    print("\nPer-firewall routing & zone:")
    print(f"{'Firewall':<18} {'Mgmt IP':<15} {'VR':<16} {'Interface':<18} {'Zone':<24}")
    print("-" * 96)
    for r in rows:
        print(f"{r['fw']:<18} {r['ip']:<15} {r['vr']:<16} {r['iface']:<18} {r['zone']:<24}")

    print("\nDone.\n")


if __name__ == "__main__":
    main()
