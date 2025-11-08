#!/usr/bin/env python3
"""
mac_address_inventory.py — tiny, local MAC address inventory & scanner

Features
- Keeps a CSV inventory at a path you choose (default: ./mac_inventory.csv)
- Scan a subnet (ping sweep) and then read the ARP table to discover MAC/IPs
- Auto-enrich with hostname (reverse DNS) and vendor (OUI) via 'manuf' if installed
- Query by MAC/IP/hostname/vendor, list all, and label devices with a friendly name/notes

Usage (examples)
  # Install optional deps (vendor lookup & faster network info)
  pip install manuf

  # Quick scan of your LAN (change subnet if needed)
  python mac_address_inventory.py scan --net 192.168.1.0/24

  # List everything we know
  python mac_address_inventory.py list

  # Label a device you recognized
  python mac_address_inventory.py label --mac AA:BB:CC:DD:EE:FF --name "Living Room TV" --notes "Samsung 65in"

  # Find by partial MAC / IP / name / vendor
  python mac_address_inventory.py find --q samsung
  python mac_address_inventory.py find --q AA:BB

Inventory Columns
  mac, name, notes, vendor, hostname, ip_last_seen 

Tested on Windows 11, needs standard 'ping' and 'arp' commands to work.
"""

import argparse
import csv
import datetime as dt
import ipaddress
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

CSV_DEFAULT = os.path.abspath(r"D:\Jari\Local\mac_addr_inventory.csv")

# -------- Utilities --------

def normalize_mac(mac: str) -> str:
    """
    Normalize MAC address to format AA:BB:CC:DD:EE:FF (uppercase).
    If input is invalid, return as-is uppercased.

    Args:
        mac (str): Input MAC address string.
    Returns:
        str: Normalized MAC address or original uppercased string if invalid.
    """
    if not mac:
        return ""
    m = re.sub(r'[^0-9a-fA-F]', '', mac)
    if len(m) != 12:
        return mac.upper()
    return ":".join(m[i:i+2] for i in range(0, 12, 2)).upper()


def now_iso() -> str:
    """
    Return current datetime in ISO 8601 format (YYYY-MM-DDTHH:MM:SS).

    Returns:
        str: Current datetime in ISO 8601 format.
    """

    return dt.datetime.now().isoformat(timespec="seconds")


def read_csv_inventory(path: str) -> dict:
    """
    Read inventory CSV and return dict keyed by normalized MAC address.

     Args:
        path (str): Path to CSV file.
    Returns:
        dict: Inventory dictionary keyed by MAC address.
    """
    inv = {}
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            for row in r:
                mac = normalize_mac(row.get("mac",""))
                if mac:
                    inv[mac] = {
                        "mac": mac,
                        "name": row.get("name",""),
                        "notes": row.get("notes",""),
                        "vendor": row.get("vendor",""),
                        "hostname": row.get("hostname",""),
                        "ip_last_seen": row.get("ip_last_seen",""),
                    }
    return inv

def write_csv_inventory(path: str, inv: dict) -> None:
    """
    Write inventory dict to CSV file.
    Args:
        path (str): Path to CSV file.
        inv (dict): Inventory dictionary keyed by MAC address.
    """
    cols = ["mac","name","notes","vendor","hostname","ip_last_seen"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for mac in sorted(inv.keys()):
            w.writerow(inv[mac])


def get_vendor(mac: str) -> str:
    """
    Return vendor string using manuf if available, else ''.

    Args:
        mac (str): MAC address string.
    Returns:
        str: Vendor name or empty string.
    """
    try:
        from manuf import manuf
        parser = manuf.MacParser()
        return parser.get_manuf_long(mac) or parser.get_manuf(mac) or ""
    except Exception:
        return ""


def reverse_dns(ip: str) -> str:
    """
    Return reverse DNS hostname for given IP, or '' if not found.

    Args:
        ip (str): IP address string.
    Returns:
        str: Hostname or empty string.
    """
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def _ping(ip: str) -> bool:
    """
    Ping a single IP address. Returns True if reachable, else False.
    
    Args:
        ip (str): IP address string.
    Returns:
        bool: True if ping successful, else False.
    """
    sys = platform.system().lower()
    if "windows" in sys:
        cmd = ["ping", "-n", "1", "-w", "400", ip]   # 400ms timeout
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]     # 1s timeout
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


def ping_sweep(cidr: str, max_workers: int = 128) -> None:
    """
    Ping all hosts in subnet to populate ARP cache. 

    Args:
        cidr (str): CIDR subnet string, e.g., '192.168.1.0/24'.
        max_workers (int): Max concurrent threads for pinging.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    targets = [str(h) for h in net.hosts()]
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_ping, ip): ip for ip in targets}
        for _ in as_completed(futs):
            pass  # no output, we only want ARP to be populated


def parse_arp_windows(text: str):
    """ 
    Parse Windows 'arp -a' output and return list of (ip, mac) tuples.
    
    Args:
        text (str): Output text from 'arp -a' command.
    Returns:
        list: List of (ip, mac) tuples.
    """
    # Example: "  192.168.1.1          00-11-22-33-44-55     dynamic"
    entries = []
    for line in text.splitlines():
        if re.search(r'\d+\.\d+\.\d+\.\d+', line) and re.search(r'([0-9a-f]{2}-){5}[0-9a-f]{2}', line, re.I):
            parts = line.split()
            try:
                ip = parts[0]
                mac_raw = parts[1]
                mac = normalize_mac(mac_raw.replace("-",":"))
                entries.append((ip, mac))
            except Exception:
                continue
    return entries


def parse_arp_unix(text: str):
    """ 
    Parse Unix 'arp -an' output and return list of (ip, mac) tuples.
    
    Args:
        text (str): Output text from 'arp -an' command.
    Returns:
        list: List of (ip, mac) tuples.
    """
    # Example (macOS/Ubuntu): "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ether]"
    entries = []
    for line in text.splitlines():
        m_ip = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
        m_mac = re.search(r'(([0-9a-f]{2}:){5}[0-9a-f]{2})', line, re.I)
        if m_ip and m_mac:
            ip = m_ip.group(1)
            mac = normalize_mac(m_mac.group(1))
            entries.append((ip, mac))
    return entries


def get_arp_entries() -> list[tuple[str,str]]:
    """
    Get ARP table entries as list of (ip, mac) tuples.

    Returns:
        list: List of (ip, mac) tuples from ARP table.
    """
    sys = platform.system().lower()
    try:
        if "windows" in sys:
            res = subprocess.run(["arp","-a"], capture_output=True, text=True)
            return parse_arp_windows(res.stdout)
        else:
            # Try 'arp -an' first, fall back to 'ip neigh'
            res = subprocess.run(["arp","-an"], capture_output=True, text=True)
            out = res.stdout
            entries = parse_arp_unix(out)
            if entries:
                return entries
            # fallback
            res2 = subprocess.run(["ip","neigh","show"], capture_output=True, text=True)
            entries2 = []
            for line in res2.stdout.splitlines():
                m_ip = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})', line, re.I)
                if m_ip:
                    ip = m_ip.group(1)
                    mac = normalize_mac(m_ip.group(2))
                    entries2.append((ip, mac))
            return entries2
    except Exception:
        return []

# -------- Commands --------

def cmd_scan(args):
    """
    Scan subnet (optional) and read ARP table to update inventory CSV.
    1. Read existing inventory from CSV.
    2. If --subnet provided, ping sweep to populate ARP cache.
    3. Read ARP table and update inventory with new entries.
    4. Write updated inventory back to CSV.
    """
    inventory = read_csv_inventory(args.csv)
    if args.subnet:
        print(f"[scan] Pinging subnet {args.subnet} to populate ARP...")
        ping_sweep(args.subnet)
    print("[scan] Reading ARP table...")
    arp = get_arp_entries()
    if not arp:
        print("[scan] No ARP entries found. Try specifying --subnet and run as admin/root if needed.")
    now = now_iso()
    for ip, mac in arp:
        if not mac:
            continue
        mac_n = normalize_mac(mac)
        entry = inventory.get(mac_n, {
            "mac": mac_n,
            "name": "",            
            "notes": "",
            "vendor": "",
            "hostname": "",
            "ip_last_seen": "",
        })
        entry["ip_last_seen"] = ip
        if not entry.get("hostname"):
            entry["hostname"] = reverse_dns(ip)
        if not entry.get("vendor"):
            v = get_vendor(mac_n)
            if v: entry["vendor"] = v
        inventory[mac_n] = entry
    write_csv_inventory(args.csv, inventory)
    print(f"[scan] Updated {args.csv} with {len(arp)} ARP devices (inventory now {len(inventory)} rows).")


def cmd_list(args):
    """
    List all inventory rows in a pretty table.
    """
    inventory = read_csv_inventory(args.csv)
    if not inventory:
        print("(empty inventory)")
        return
    cols = ["mac","name","notes","vendor","hostname","ip_last_seen"]
    # Pretty print with fixed widths
    def trunc(s, n=30):
        s = s or ""
        return (s[:n-1] + "…") if len(s) > n else s
    print(" | ".join([
        "MAC".ljust(17),
        "NAME".ljust(22),
        "NOTES".ljust(32),
        "VENDOR".ljust(28),
        "HOSTNAME".ljust(28),
        "IP".ljust(15),
    ]))
    print("-"*170)
    for mac, row in sorted(inventory.items()):
        print(" | ".join([
            mac.ljust(17),
            trunc(row["name"],22).ljust(22),
            trunc(row["notes"],32).ljust(32),
            trunc(row["vendor"],28).ljust(28),
            trunc(row["hostname"],28).ljust(28),
            (row["ip_last_seen"] or "").ljust(15),
        ]))


def cmd_find(args):
    """
    Search inventory by partial MAC/IP/hostname/vendor/name/notes.
    """
    q = (args.q or "").strip().lower()
    if not q:
        print("Provide --q <query> (partial MAC/name/notes/vendor/hostname/IP).")
        return
    inventory = read_csv_inventory(args.csv)
    hits = []
    for mac, row in inventory.items():
        hay = "|".join([
            mac,
            row.get("name",""),
            row.get("notes",""),
            row.get("vendor",""),
            row.get("hostname",""),
            row.get("ip_last_seen",""),
        ]).lower()
        if q in hay:
            hits.append(row)
    if not hits:
        print("(no matches)")
        return
    for r in hits:
        print(f"{r['mac']}  {r['name']:<22} {r['notes']} {r['vendor']:<28} {r['hostname']:<28}  {r['ip_last_seen']:<15}")

def cmd_label(args):
    mac = normalize_mac(args.mac or "")
    if not mac:
        print("Provide --mac AA:BB:CC:DD:EE:FF")
        return
    inventory = read_csv_inventory(args.csv)
    if mac not in inventory:
        # create a new row if user wants to pre-label
        inventory[mac] = {
            "mac": mac,
            "name": args.name or "",
            "notes": args.notes or "",
            "vendor": get_vendor(mac) or "",
            "hostname": "",
            "ip_last_seen": "",
        }
    else:
        if args.name is not None:
            inventory[mac]["name"] = args.name
        if args.notes is not None:
            inventory[mac]["notes"] = args.notes
        if not inventory[mac].get("vendor"):
            inventory[mac]["vendor"] = get_vendor(mac) or ""
    write_csv_inventory(args.csv, inventory)
    print(f"[label] Set for {mac}: name='{args.name or inventory[mac]['name']}', notes='{args.notes or inventory[mac]['notes']}'")

def build_arg_parser():
    """
    Build the argument parser for command-line interface.

    Returns:
        argparse.ArgumentParser: Configured argument parser.
    """
    p = argparse.ArgumentParser(description="Local MAC address inventory & scanner")
    p.add_argument("--csv", default=CSV_DEFAULT, help=f"Path to inventory CSV (default: {CSV_DEFAULT})")
    sub = p.add_subparsers(dest="cmd")

    # scan
    s1 = sub.add_parser("scan", help="Ping a subnet (optional) and import ARP table into inventory")
    s1.add_argument("--subnet", help="CIDR subnet to ping first, e.g., 192.168.1.0/24")
    s1.set_defaults(func=cmd_scan)

    # list
    s2 = sub.add_parser("list", help="List all inventory rows")
    s2.set_defaults(func=cmd_list)

    # find
    s3 = sub.add_parser("find", help="Search inventory by partial MAC/IP/hostname/vendor/name/notes")
    s3.add_argument("--q", required=True, help="Query string")
    s3.set_defaults(func=cmd_find)

    # label
    s4 = sub.add_parser("label", help="Add or update a friendly name/notes for a device")
    s4.add_argument("--mac", required=True, help="MAC address to label")
    s4.add_argument("--name", default=None, help="Friendly name (e.g., 'Living Room TV')")
    s4.add_argument("--notes", default=None, help="Optional notes")
    s4.set_defaults(func=cmd_label)

    return p

def main():
    p = build_arg_parser()
    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return
    args.func(args)

if __name__ == "__main__":
    main()