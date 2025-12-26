# MQTT Stealth C&C (Command & Control)

This project implements a covert Command & Control (C&C) channel over the MQTT protocol. It is designed to evade detection by mimicking legitimate IoT sensor traffic on a public broker.

## Protocol Design and Steganography

The core requirement was to operate on a public topic ("sensors") without being detected as a botnet. To achieve this, we designed a custom protocol that hides instructions within what appears to be standard telemetry data.

### 1. The Covert Channel
Instead of sending raw commands (e.g., {"cmd": "ls"}), the Controller and Bot exchange JSON packets that mimic environmental sensors (Thermometers, Hygrometers).

**Packet Structure on Wire:**
```json
{
  "sensor_id": "sensor_8492",
  "temp": 24.5,
  "hum": 45.0,
  "bat": 98,
  "fingerprint": "a3f1... (Hex String)"
}

```

* **Visible Layer:** sensor_id, temp, hum, and bat are visible and randomized to look realistic.
* **Hidden Payload:** The actual command is encrypted and stored in the "fingerprint" field. To an observer, this looks like a standard data integrity checksum or device hash.

### 2. Encryption and Key Derivation

We utilize **AES-256-CBC** for encryption. The key is **not** transmitted. Instead, it is dynamically derived from the *visible* packet data combined with a hidden secret.

* **Key Formula:** Key = MD5(sensor_id + temp + hum + bat + SALT)
* **Salt:** A pre-shared secret string ("S4ur0ns_S3cr3t_S4lt_2025") known only to the bot and controller.

**Security Features:**

* **Confidentiality:** Without the Salt, the key cannot be generated from the sensor data.
* **Obfuscation:** The payload is hidden in plain sight as a "fingerprint".
* **Polymorphism:** Since temperature and humidity values change slightly with every packet, the Encryption Key changes for every single message. Identical commands produce completely different ciphertexts, preventing replay attacks and pattern analysis.

## Requirements

The solution is written in Python 3.

**Dependencies:**

* paho-mqtt (Standard MQTT client)
* pycryptodome (For AES encryption)

**Installation:**

```bash
pip install -r requirements.txt

```

## How to Run

### 1. Setup

Ensure dependencies are installed on both the target machine and the controller machine:

```bash
pip install -r requirements.txt

```

### 2. Start the Bot (Implant)

Run this on the target ("infected") machine. It will connect to the broker and wait silently.

```bash
python3 bot.py

```

Output: `[*] Bot sensor_XXXX listening...`

### 3. Start the Controller

Run this on your local machine. It provides a CLI to issue commands.

```bash
python3 controller.py

```

### 4. Controller Commands

Once the controller is running, you can type the following commands to control the bots:

* **ping**: Checks if bots are alive.
* **w**: Lists logged-in users on the bot.
* **id**: Shows the user ID running the bot.
* **ls <dir>**: Lists the contents of a directory (e.g., ls /tmp).
* **exec <cmd>**: Executes an arbitrary shell command (e.g., exec ps aux).
* **copy <file>**: Reads a file from the bot (e.g., copy /etc/passwd).

## Testing Procedure

To verify the solution works as intended using the provided sandbox environment:

1. **Deploy Bot:** Upload `bot.py` and `requirements.txt` to the remote sandbox server (e.g., via SCP).
2. **Install Remote Dependencies:** Run `pip install -r requirements.txt` on the remote server.
3. **Run Bot:** Execute `python3 bot.py` on the remote server.
4. **Run Controller:** Execute `python3 controller.py` on your local machine (ensure you have internet access to reach the public MQTT broker).
5. **Verify Communication:** Type `ping` in the controller terminal. If the bot replies with "Pong", the encrypted covert channel is established.

## Files

* **bot.py**: The agent running on the target. Subscribes to "sensors", regenerates keys from packet data, decrypts fingerprints, executes commands, and replies with fake sensor data containing encrypted results.
* **controller.py**: The master interface. Encrypts commands into fake sensor packets and decrypts the responses.
* **requirements.txt**: List of required python libraries.

## Configuration

* **Broker:** 147.32.82.209
* **Port:** 1883
* **Topic:** sensors

