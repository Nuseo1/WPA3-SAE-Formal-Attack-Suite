#!/usr/bin/env bash
# ============================================================
# airgeddon Live Monitor + Auto-Close (Version 1 - Bugfixed)
# ============================================================

# --- Prevent multiple instances ---
LOCKDIR="/tmp/ag_monitor.lockdir"
PIDFILE="$LOCKDIR/pid"
if [ -d "$LOCKDIR" ]; then
    if [ -f "$PIDFILE" ] && ps -p "$(cat "$PIDFILE")" >/dev/null 2>&1; then
        echo "Monitoring is already running (PID $(cat "$PIDFILE"))."
        exit 1
    else
        rm -rf "$LOCKDIR"
    fi
fi
mkdir "$LOCKDIR" 2>/dev/null || { echo "Lockdir error."; exit 1; }
echo $$ > "$PIDFILE"
MAIN_PID=$$

BG_PIDS=()
PW_BASELINE="/tmp/.ag_pw_baseline_$$"
cleanup() {
    trap - EXIT INT TERM
    echo -e "\nStopping monitor..."
    disown -a 2>/dev/null
    kill "${BG_PIDS[@]}" 2>/dev/null
    rm -f "$PW_BASELINE" 2>/dev/null
    rm -rf "$LOCKDIR"
}
trap cleanup EXIT
trap 'exit 0' INT TERM

# --- Configuration ---
AG_BASE="/tmp/"
PAT_ATTEMPTS="*/ag*/www/ag.et_attempts.txt"
PAT_CURRENTPASS="*/ag*/www/ag.et_currentpass.txt"
PAT_CLTS="*/ag*/clts.txt"

# Hit directory (one file per SSID, written by airgeddon)
PW_OUTPUT_DIR="/root/Schreibtisch/airgeddon-dev/plugins/output"
PW_PATTERN="evil_twin_captive_portal_password-*.txt"

# Should the monitor close itself after a hit?
AUTO_CLOSE_MONITOR="true"   # "true" or "false"

# --- Sound (sox & player with fallback for root sessions) ---
SOUND_FILE="/root/beep_1.5s.wav"
if command -v sox >/dev/null 2>&1 && [ ! -f "$SOUND_FILE" ]; then
    sox -n "$SOUND_FILE" synth 0.5 sin 880 vol 0.3 2>/dev/null
fi

play_sound() {
    [ ! -f "$SOUND_FILE" ] && return
    (
        paplay "$SOUND_FILE" 2>/dev/null || \
        play -q "$SOUND_FILE" 2>/dev/null || \
        aplay -q "$SOUND_FILE" 2>/dev/null
    ) &
    disown 2>/dev/null
}

# --- Stop function for the Python attack ---
stop_python_attack() {
    local pat='wpa3_sae_formal_attacks.*\.py'

    echo "[INFO] Sending SIGTERM to Python attack..."
    pkill -TERM -f "$pat" 2>/dev/null

    # Wait up to 10 seconds for graceful termination
    local i
    for i in $(seq 1 20); do
        if ! pgrep -f "$pat" >/dev/null 2>&1; then
            echo "[OK] Python attack stopped cleanly."
            return 0
        fi
        sleep 0.5
    done

    # Emergency stop: SIGKILL to main and child processes
    echo "[WARN] Process not responding, sending SIGKILL to all related processes..."
    pkill -KILL -f "$pat" 2>/dev/null
    sleep 1

    if pgrep -f "$pat" >/dev/null 2>&1; then
        echo "[WARN] Process is still running:"
        pgrep -af "$pat"
    else
        echo "[OK] Python attack terminated (SIGKILL)."
    fi
}

# --- Find active airgeddon directory & log files ---
AG_DIR=$(find "$AG_BASE" -maxdepth 3 -type d -name "www" -path "*/ag*/www" -printf '%T@ %h\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)

if [ -n "$AG_DIR" ] && [ -d "$AG_DIR" ]; then
    attempt_file="$AG_DIR/www/ag.et_attempts.txt"
    currentpass_file="$AG_DIR/www/ag.et_currentpass.txt"
    clts_file="$AG_DIR/clts.txt"
else
    attempt_file=$(find "$AG_BASE" -type f -path "$PAT_ATTEMPTS"       -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
    currentpass_file=$(find "$AG_BASE" -type f -path "$PAT_CURRENTPASS" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
    clts_file=$(find "$AG_BASE" -type f -path "$PAT_CLTS"             -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
fi

[ -z "$attempt_file" ] && [ -z "$clts_file" ] && [ -z "$currentpass_file" ] && \
    { echo "No airgeddon logs found. Is an attack running?"; exit 1; }

echo "Monitoring:"
[ -n "$attempt_file" ]     && echo "  Password attempts:  $attempt_file"
[ -n "$currentpass_file" ] && echo "  Live password box:  $currentpass_file"
[ -n "$clts_file" ]        && echo "  New clients:        $clts_file"
echo "  Hit directory:      $PW_OUTPUT_DIR (NEW files only from now on)"
echo "-------------------------------------------"

# --- 1) Failed password attempts (file is appended -> tail) ---
if [ -n "$attempt_file" ]; then
    tail -n0 -F -s 1 "$attempt_file" 2>/dev/null | while read -r line; do
        [ -n "$line" ] && echo "[ATTEMPT] $line" && play_sound
    done &
    BG_PIDS+=($!)
fi

# --- 1b) Live input (file is overwritten -> polling, without redirection error) ---
if [ -n "$currentpass_file" ]; then
    (
        last_mtime=0
        last_content=""
        if [ -f "$currentpass_file" ]; then
            last_mtime=$(stat -c %Y "$currentpass_file" 2>/dev/null || echo 0)
            last_content=$(cat "$currentpass_file" 2>/dev/null | tr -d '\r\n')
        fi
        while true; do
            if [ -f "$currentpass_file" ]; then
                mtime=$(stat -c %Y "$currentpass_file" 2>/dev/null || echo 0)
                content=$(cat "$currentpass_file" 2>/dev/null | tr -d '\r\n')
                if [ -n "$content" ] && { [ "$mtime" != "$last_mtime" ] || [ "$content" != "$last_content" ]; }; then
                    echo "[INPUT] $content"
                    play_sound
                    last_mtime="$mtime"
                    last_content="$content"
                fi
            fi
            sleep 1
        done
    ) &
    BG_PIDS+=($!)
fi

# --- 2) New clients (with debouncing) ---
declare -A recent_clients
debounce_interval=5
last_sound_time=0
if [ -n "$clts_file" ]; then
    while read -r line; do
        MAC=$(echo "$line" | awk '{print $5}')
        [ -n "${recent_clients[$MAC]}" ] && continue
        recent_clients[$MAC]=1
        INFO=$(echo "$line" | awk '{print "IP: "$3", MAC: "$5}')
        echo "[CLIENT] $INFO"
        now=$(date +%s)
        if (( now - last_sound_time >= debounce_interval )); then
            play_sound
            last_sound_time=$now
        fi
    done < <(tail -n0 -F -s 1 "$clts_file" 2>/dev/null | grep --line-buffered "DHCPACK") &
    BG_PIDS+=($!)
fi

# --- 3) Valid password (NEW files only, excluding donation footer false positives) ---
touch "$PW_BASELINE" 2>/dev/null
(
    while true; do
        HIT_FILE=$(find "$PW_OUTPUT_DIR" -maxdepth 1 -type f -name "$PW_PATTERN" \
                        -size +0c -newer "$PW_BASELINE" -print -quit 2>/dev/null)

        if [ -n "$HIT_FILE" ] && [ -f "$HIT_FILE" ]; then
            # Ignore empty lines, separator lines, and the airgeddon donation footer (EN/DE)
            PASS=$(grep -Ev '^[[:space:]]*$|^[-=*]+$|v1s1t0r|PayPal|Spende|Kryptowährung|donation|cryptocurrency|liked this script|Contributing' "$HIT_FILE" 2>/dev/null | tail -n 1 | tr -d '\r')

            if [ -n "$PASS" ]; then
                echo "[HIT] $PASS"
                echo "[HIT] File: $HIT_FILE"
                play_sound
                notify-send "airgeddon" "VALID Password: $PASS" 2>/dev/null &

                # Do NOT delete/truncate the file – it contains your result!
                touch "$PW_BASELINE" 2>/dev/null

                stop_python_attack

                if [ "$AUTO_CLOSE_MONITOR" = "true" ]; then
                    sleep 0.5
                    kill -TERM "$MAIN_PID" 2>/dev/null
                fi
                break
            fi
        fi

        sleep 1
    done
) &
BG_PIDS+=($!)

# --- Wait until interrupted ---
wait 2>/dev/null
