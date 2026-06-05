# WPA3-SAE Formal Attack Suite

> ⚠️ **FOR AUTHORIZED RESEARCH & ISOLATED TEST ENVIRONMENTS ONLY**

## Overview

This tool implements **13 formal attacks against the WPA3 SAE (Simultaneous Authentication of Equals)** handshake protocol, as documented in the academic paper:

> *"What a Mesh: Formal Security Analysis of WPA3 SAE Wireless Authentication"*
> Metere et al., arXiv:2603.23352v1, 2026
> Errata: IEEE 802.11-24/0027r0-r2 & 0744r1 (Accepted Patches)

The suite is designed for **security researchers, Wi-Fi protocol engineers, and penetration testers** conducting authorized assessments of WPA3-capable access points.

---

## 🆕 What's New: Multi-Group Support (Groups 19–24)

Previously, the suite exclusively supported Group 19 (ECC, NIST P-256) for SAE parameter extraction and injection. The new script (`wpa3_sae_formal_attacks_github.py` / `WPA3-SAE_DoS_Orchestrator_20_list-new.py`) extends this to full support for both Scalar and Finite Field elements across Groups 19–24, covering additional ECC and FFC groups defined in the SAE standard.

The required group-specific parameter values are extracted using `sae_extractor_arxiv_all_groups.py`, which replaces `sae_extractor.py` for multi-group scenarios.

---

## Implemented Attacks

| # | Attack Name | Type | Paper Reference |
|---|---|---|---|
| 1 | `commit_flood` | DoS (Cookie Guzzler) | §VI-B |
| 2 | `reflection_attack` | Auth Bypass | §VI-A, Erratum #23 |
| 3 | `memory_exhaustion` | Resource DoS | §VI-B |
| 4 | `deadlock` | State Machine Deadlock | §VI-B, Errata #16, #17 |
| 5 | `zero_scalar` | Cryptographic Weakness | §12.4.5.4 |
| 6 | `invalid_curve` | Information Leak | §12.4.5.4 |
| 7 | `downgrade` | Group Downgrade | §12.4.8.6.4, Erratum #19 |
| 8 | `open_auth` | Legacy DoS | IEEE 802.11 |
| 9 | `unknown_pw_id` | Memory DoS / Stall | §VI-C, Errata #1, #16 |
| 10 | `simultaneous_pw_id_conflict` | Non-termination Loop | §VI-C-1 |
| 11 | `group_mismatch_tiebreaker_deadlock` | State Machine Deadlock | §VI-C-3, Erratum #M |
| 12 | `threshold_boundary` | Spec Flaw / DoS | §12.4.6, App.B.C |
| 13 | `silent_discard` | Error Handling Test | §12.4.8.6.3, App.B.K |

---

## Requirements

- Python 3.8+
- Linux (monitor-mode capable Wi-Fi adapter required)
- Root privileges (`sudo`)
- Wi-Fi adapter(s) placed in monitor mode

### Python Dependencies

```bash
pip install scapy
```

### System Dependencies

```bash
sudo apt install iw wireless-tools
```

### ⚠️ Requirement: wpa_supplicant 2.11
For `sae_extractor_arxiv_all_groups.py` to function correctly with the new group definitions, **wpa_supplicant version 2.11** must be installed.

**Kali Linux users:** The standard Kali Linux repositories typically ship an older version of wpa_supplicant. Using an outdated version will result in extraction errors when targeting groups other than Group 19. Please install version 2.11 manually before using the multi-group extractor.

---

## Setup

### 1. Place adapter(s) in monitor mode

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set monitor control
sudo ip link set wlan0 up
# Or using airmon-ng:
sudo airmon-ng start wlan0
```

### 2. Fill in target configuration in the script

Edit the following constants in `wpa3_sae_formal_attacks_github.py`:

```python
TARGET_BSSID_5GHZ   = "AA:BB:CC:DD:EE:11"  # Replace with your AP's 5GHz BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:12"  # Replace with your AP's 2.4GHz BSSID
MANUAL_CHANNEL_5GHZ   = "36"               # Channel of your 5GHz AP
MANUAL_CHANNEL_2_4GHZ = "6"                # Channel of your 2.4GHz AP
```

### 3. Add SAE parameters (optional, for cryptographic precision)

Use the companion script `sae_extractor_arxiv_all_groups.py` to extract real SAE scalars and finite field elements from captured handshakes. Insert them into the `SAE_SCALARS_*` and `SAE_FINITES_*` dictionaries inside the main script. Without these values, the tool falls back to random bytes.

### 4. Configure Known MACs (for `memory_exhaustion` attack)

To maximize the effectiveness of the `memory_exhaustion` attack, use the output from `capture_known_macs.py` and insert the captured STA MAC addresses into the corresponding lists:

```python
# Known MACs for memory_exhaustion (Output from capture_known_macs.py)
KNOWN_STA_MACS_5GHZ = [
    # "11:22:33:44:55:66", ...
]
KNOWN_STA_MACS_2_4GHZ = [
    # "AA:BB:CC:DD:EE:FF", ...
]
```

### 5. Configure adapter-to-attack mapping

```python
ADAPTER_CONFIGURATION = {
    "wlan0mon": {"band": "5GHz",   "attack": "commit_flood"},
    "wlan1mon": {"band": "2.4GHz", "attack": "unknown_pw_id"},
}
```

## Usage

```bash
# Use the configuration defined in the script
sudo python3 wpa3_sae_formal_attacks_github.py

# Override attack and interfaces via CLI
sudo python3 wpa3_sae_formal_attacks_github.py \
    --interfaces wlan0mon,wlan1mon \
    --band 5GHz,2.4GHz \
    --attack commit_flood

# Override only the attack type (keep configured interfaces)
sudo python3 wpa3_sae_formal_attacks_github.py --attack deadlock

# Dry-run (construct packets without sending)
sudo python3 wpa3_sae_formal_attacks_github.py --dry-run --attack zero_scalar

# Show full attack encyclopedia
sudo python3 wpa3_sae_formal_attacks_github.py --help
```

## Optional: Automatic Channel Scanner

Set `SCANNER_INTERFACE` to a monitor-mode interface to enable automatic channel tracking:

```python
SCANNER_INTERFACE = "wlan2mon"
```

The scanner will detect the AP's current channel and update all attack processes automatically.

## References

- Metere et al. (2026): *"What a Mesh: Formal Security Analysis of WPA3 SAE Wireless Authentication"*, arXiv:2603.23352v1
- Vanhoef & Ronen (2020): *"Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd"*
- IEEE Std 802.11-2020, §12.4 (SAE Authentication)
- IEEE 802.11-24/0027r0-r2, 0744r1 (Accepted Errata)
