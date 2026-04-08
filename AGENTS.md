# AGENTS.md — FIPS BLE Component Development Guide

Instructions for AI agents working on the `fips_ble` ESPHome component.

## Hardware Setup

Two ESP32 boards on this machine:

| Board | Serial Port | Chip | Purpose | Flash? |
|---|---|---|---|---|
| ESP32-S3 | `/dev/ttyACM0` | ESP32-S3-PICO-1 (rev v0.2) | **Active development target** | YES |
| ESP32-D0WD | `/dev/ttyUSB0` | ESP32-D0WDQ6 | Runs old microfips firmware (interference source) | **NEVER** |

The D0WD runs stale microfips with test addresses (`02:00:00:00:00:FF`) that spams the FIPS daemon with bad MSG1s. Do not flash it.

## Flashing the ESP32-S3

```bash
PYTHONPATH=/home/ubuntu/src/esphome python3 -m esphome compile /tmp/esphome-flash/fips-esp32s3.yaml
PYTHONPATH=/home/ubuntu/src/esphome python3 -m esphome upload /tmp/esphome-flash/fips-esp32s3.yaml --device /dev/ttyACM0
```

**Always confirm with the user before flashing.**

## Serial Log Monitoring (USB_SERIAL_JTAG)

The ESP32-S3 uses USB_SERIAL_JTAG for serial output. This requires special handling:

### Logger config (required in YAML):
```yaml
logger:
  level: DEBUG
  hardware_uart: USB_SERIAL_JTAG
```

### The RTS reset problem:
ESPHome's upload uses `esptool --after hard-reset` which toggles RTS. On ESP32-S3 USB_SERIAL_JTAG, this always enters **download mode** (`boot:0x0 (DOWNLOAD)`) instead of normal boot. The app never runs, so no logs appear.

### Working reset sequence:
After ESPHome flashes (which leaves the chip in download mode), use `esptool --after watchdog-reset` to boot normally:

```bash
# Flash (leaves chip in download mode)
PYTHONPATH=/home/ubuntu/src/esphome python3 -m esphome upload /tmp/esphome-flash/fips-esp32s3.yaml --device /dev/ttyACM0

# Watchdog reset into normal boot (boot:0x8 SPI_FAST_FLASH_BOOT)
python3 -m esptool --port /dev/ttyACM0 --chip esp32s3 --after watchdog-reset --no-stub chip-id

# Wait ~3s for USB reconnect, then read logs
python3 -c "
import serial, time, sys, os
for _ in range(20):
    if os.path.exists('/dev/ttyACM0'):
        try:
            ser = serial.Serial('/dev/ttyACM0', 115200, timeout=0.1)
            break
        except: pass
    time.sleep(0.5)
ser.dtr = False; ser.rts = False
buf = b''
deadline = time.time() + 20
while time.time() < deadline:
    try:
        n = ser.in_waiting
        if n > 0:
            chunk = ser.read(n)
            buf += chunk
            sys.stdout.buffer.write(chunk)
            sys.stdout.flush()
        else:
            time.sleep(0.02)
    except OSError:
        break
ser.close()
"
```

### Reading logs from an already-running chip:
If the chip is already booted (not in download mode), just open the serial port without any DTR/RTS toggling:

```bash
python3 -c "
import serial, time, sys
ser = serial.Serial('/dev/ttyACM0', 115200, timeout=0.1)
ser.dtr = False; ser.rts = False
buf = b''
deadline = time.time() + 15
while time.time() < deadline:
    n = ser.in_waiting
    if n > 0:
        chunk = ser.read(n)
        buf += chunk
        sys.stdout.buffer.write(chunk)
        sys.stdout.flush()
    else:
        time.sleep(0.02)
ser.close()
"
```

### Signs the chip is in download mode:
```
rst:0x15 (USB_UART_CHIP_RESET),boot:0x0 (DOWNLOAD(USB/UART0))
waiting for download
```

### Signs the chip booted normally:
```
rst:0x15 (USB_UART_CHIP_RESET),boot:0x8 (SPI_FAST_FLASH_BOOT)
```
Followed by ESP-IDF bootloader output and ESPHome log lines.

## FIPS Daemon

The FIPS daemon runs as a systemd service on this machine:

```bash
sudo systemctl status fips          # check status
sudo systemctl restart fips         # restart
sudo journalctl -u fips --since "2 min ago" --no-pager  # recent logs
```

Key config files:
- `/etc/fips/fips.yaml` — daemon config (addr, disable_tiebreaker, peers)
- `/etc/fips/fips.key` — daemon nsec key
- `/etc/fips/fips.yaml.bak` — backup with peers section

The daemon currently has **no peers configured** (accepts any initiator). The S3's derived identity was accepted without being listed as a peer.

## Key Derivation

Per-device identity keys are derived at compile time:
```
identity_secret = SHA256("esphome:fips_ble:" + identity_seed)
```
Where `identity_seed` defaults to `CORE.name` (the `esphome:` name in YAML).

Current keys for reference:
- **ESP32-S3**: seed=`"fips-esp32s3"`, pubkey=`02673410bfed3f2ba8d7407c5ce26cf75a5d5714501a1d2c92174e3b63cf03a2f3`
- **FIPS daemon**: nsec=`nsec1h0yfqer2tcyy58r4gaypdajfqmpp6wgusq5qgdgw2lw6xrlxkpgsqskr6m`, pubkey=`03b3989043c68d9c2d3c8f949d73e61cae27997993432c3dbbd8498117d92d95bb`

## FIPS Noise Protocol Deviations (GROUND TRUTH)

Do NOT follow standard Noise spec. FIPS/microfips have intentional deviations:

| Deviation | Standard Noise | FIPS Implementation |
|---|---|---|
| **D1** (AAD) | `h` (running hash) | Empty (0 bytes) |
| **D2** (IK `se`) | `DH(s_initiator, re_responder)` | `DH(e_initiator_priv, rs_responder_pub)` |
| **D3** (ECDH) | Raw shared secret | `SHA256(shared_x_coordinate)` |
| **Parity** | Standard | Force `0x02` prefix (even parity) for pre-message hash |

## Wire Format Constants

```
ESTABLISHED_HEADER_SIZE = 16  (IDX_SIZE=4 + counter=8 + direction_flags=4)
COMMON_PREFIX_SIZE = 4      (ver_phase=1 + flags=1 + payload_len=2)
TAG_SIZE = 16               (ChaChaPoly1305)
INNER_HEADER_SIZE = 5       (timestamp=4 + msg_type=1)

payload_len for phase=0: inner_plaintext size ONLY
payload_len for phase=1/2: noise payload size

No 2-byte L2CAP length prefix — FIPS sends raw FMP frames over CoC.
```

## Build and Test

```bash
# Compile
PYTHONPATH=/home/ubuntu/src/esphome python3 -m esphome compile /tmp/esphome-flash/fips-esp32s3.yaml

# Python golden vector tests (48 tests, all should pass)
python3 -m pytest tests/test_fips_ble_golden_vectors/test_golden_vectors.py -v

# Component build test
./script/test_build_components -c fips_ble -t esp32-idf
```

## Git Conventions

- Branch: `fips-ble` (based on `dev`)
- Commit prefix: `[fips_ble]`
- Co-author trailer: `Co-authored-by: Sisyphus <clio-agent@sisyphuslabs.ai>`
- Reference Amperstrand/fips issues in commit messages when fixing related bugs

## Config File Location

The YAML flash config is at `/tmp/esphome-flash/fips-esp32s3.yaml` — **outside the repo** so WiFi credentials are never committed. Do not move it into the repo.
