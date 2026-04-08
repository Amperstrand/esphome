# AGENTS.md — FIPS BLE Component Development Guide

Instructions for AI agents working on the `fips_ble` ESPHome component.

## Hardware Setup

Two ESP32 boards on this machine:

| Board | Serial Port | USB VID:PID | Chip | BLE MAC | Purpose | Flash? |
|---|---|---|---|---|---|---|
| ESP32-S3 | `/dev/ttyACM0` | `303A:1001` | ESP32-S3-PICO-1 (rev v0.2) | `64:E8:33:72:01:24` (public) / `64:E8:33:72:01:E6` (random) | **Active development target** | YES |
| ESP32-D0WD | `/dev/ttyUSB0` | `10C4:EA60` | ESP32-D0WDQ6 | Unknown | Runs old microfips firmware | **NEVER** |

### Identifying the correct board

Always verify you're targeting the S3 before flashing. Use these checks:

```bash
# Check USB devices — S3 has ESP32-S3-PICO, D0WD has CP2102
lsusb | grep -E "303A:1001|10C4:EA60"

# Check serial port details — S3 uses USB JTAG/serial debug unit
python3 -c "import serial.tools.list_ports as ports; [print(f'{p.device}: {p.description}') for p in ports.comports()]"
# Expected: /dev/ttyACM0: USB JTAG/serial debug unit  (S3)
# Expected: /dev/ttyUSB0: CP2102 USB to UART Bridge Controller  (D0WD)

# Check chip identity via esptool (S3 only — D0WD may not respond to chip-id)
python3 -m esptool --port /dev/ttyACM0 --chip esp32s3 chip-id
# Expected: "Chip type: ESP32-S3-PICO-1 (LGA56) (revision v0.2)"
```

**NEVER flash `/dev/ttyUSB0`.** The D0WD runs stale microfips that connects to the FIPS daemon with old keys and interferes with handshake testing.

### D0WD interference

The D0WD's old microfips firmware connects to the FIPS daemon and presents the S3's identity pubkey. When the daemon has no peers configured, it accepts any initiator — so the D0WD can hijack the S3's peer slot. Configure the S3 as a known peer (see "FIPS Daemon" section) to prevent this.

## Flashing

Both boards run ESPHome with the `fips_ble` component. Each has a unique `esphome:` name, which produces a different `identity_seed` and therefore different cryptographic identity keys.

### ESP32-S3 (development target)

```bash
PYTHONPATH=/home/ubuntu/src/esphome python3 -m esphome compile /tmp/esphome-flash/fips-esp32s3.yaml
PYTHONPATH=/home/ubuntu/src/esphome python3 -m esphome upload /tmp/esphome-flash/fips-esp32s3.yaml --device /dev/ttyACM0
```

Board: `esp32-s3-devkitc-1` | Port: `/dev/ttyACM0` | VID:PID: `303A:1001`

### ESP32-D0WD (second peer for testing)

```bash
PYTHONPATH=/home/ubuntu/src/esphome python3 -m esphome compile /tmp/esphome-flash/fips-esp32d0wd.yaml
PYTHONPATH=/home/ubuntu/src/esphome python3 -m esphome upload /tmp/esphome-flash/fips-esp32d0wd.yaml --device /dev/ttyUSB0
```

Board: `esp32dev` | Port: `/dev/ttyUSB0` | VID:PID: `10C4:EA60`

The D0WD uses regular UART for logging (NOT USB_SERIAL_JTAG). No watchdog-reset workaround needed — `esphome upload` works normally and logs appear via `esphome logs` or a serial reader.

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

### Peer configuration (IMPORTANT for testing)

When `peers:` is configured, the daemon **only accepts MSG1 from listed identities**. This prevents the D0WD (or any rogue device) from hijacking the S3's peer slot. Configure the S3 as the sole known peer:

```yaml
peers:
  - npub: "npub19u363m5kqup2g0rfg8m5xh93cf2g0fzthnmk3kqpr746h29"
    alias: "fips-esp32s3"
```

The S3's npub is derived from its pubkey (`02673410bfed3f2ba8d7407c5ce26cf75a5d5714501a1d2c92174e3b63cf03a2f3`). To compute the npub for a new device, use:

```bash
# Derive identity from seed and compute npub
python3 -c "
import hashlib
seed = 'fips-esp32s3'
secret = hashlib.sha256(('esphome:fips_ble:' + seed).encode()).digest()
# Compute compressed pubkey from secret (requires secp256k1 or similar)
# For now, check the ESPHome dump_config log which prints the pubkey prefix
"
```

Or read it from the ESP32 serial logs after boot — `dump_config` prints `Identity pubkey: 0267..a2f3`.

### Debugging daemon peer acceptance

```bash
# Check if daemon received and accepted MSG1
sudo journalctl -u fips --since "1 min ago" --no-pager | grep -E "handshake|MSG1|MSG2|peer.*promot|decrypt.*fail"
```

## Key Derivation

Per-device identity keys are derived at compile time:
```
identity_secret = SHA256("esphome:fips_ble:" + identity_seed)
```
Where `identity_seed` defaults to `CORE.name` (the `esphome:` name in YAML).

Current keys for reference:
- **ESP32-S3**: seed=`"fips-esp32s3"`, pubkey=`02673410bfed3f2ba8d7407c5ce26cf75a5d5714501a1d2c92174e3b63cf03a2f3`
- **ESP32-D0WD**: seed=`"fips-esp32d0wd"`, pubkey=TODO (derives at compile time from its own seed)
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
