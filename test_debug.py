
import pytest
import time
import subprocess
import os
import sys
import queue
import threading
from protocol import ProtocolStack, StealthProtocolStack, DEFAULT_SALT

BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "sensors"
SALT = DEFAULT_SALT
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BOT_SCRIPT = os.path.join(SCRIPT_DIR, "bot.py")
VENV_PYTHON = os.path.join(SCRIPT_DIR, "venv", "bin", "python")
PYTHON_EXECUTABLE = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable

def test_debug_ping():
    print("\n[DEBUG] Starting test_debug_ping")
    
    # 1. Prepare Bot Code (Force Stealth Mode)
    with open(BOT_SCRIPT, 'r') as f:
        bot_code = f.read()
    
    bot_code = bot_code.replace('BROKER = "147.32.82.209"', 'BROKER = "127.0.0.1"')
    # Ensure Stealth Mode is ON and Interval is fast
    bot_code = bot_code.replace('USE_STEALTH_MODE = False', 'USE_STEALTH_MODE = True')
    bot_code = bot_code.replace('SEND_INTERVAL = 1.0', 'SEND_INTERVAL = 0.5')
    
    bot_file = os.path.join(SCRIPT_DIR, "debug_bot_gen.py")
    with open(bot_file, 'w') as f:
        f.write(bot_code)
        
    print(f"[DEBUG] Generated bot script at {bot_file}")

    # 2. Launch Bot (Inherit output)
    print("[DEBUG] Launching bot process...")
    proc = subprocess.Popen(
        [PYTHON_EXECUTABLE, bot_file],
        cwd=SCRIPT_DIR,
        stdout=sys.stdout,  # Inherit stdout so we see bot logs
        stderr=sys.stderr   # Inherit stderr
    )
    
    time.sleep(2) # Give it time to connect

    # 3. Start Controller
    print("[DEBUG] Starting Controller Stack...")
    client_id = "debug_controller"
    responses = queue.Queue()
    
    stack = StealthProtocolStack(
        node_id=client_id,
        broker=BROKER,
        port=PORT,
        topic=TOPIC,
        salt=SALT
    )
    
    def on_msg(msg):
        print(f"[DEBUG] Controller received: {msg}")
        if msg.get("type") == "response":
            responses.put(msg)

    stack.on_receive(on_msg)
    stack.start()
    time.sleep(1)

    try:
        # 4. Send Ping
        print("[DEBUG] Sending PING to ALL...")
        stack.send("ALL", "command", cmd="ping")
        
        # 5. Wait for response
        try:
            resp = responses.get(timeout=10)
            print(f"[DEBUG] Got response: {resp}")
            assert resp["output"] == "Pong"
            print("[DEBUG] SUCCESS: Pong received!")
        except queue.Empty:
            print("[DEBUG] FAILURE: Timed out waiting for pong.")
            assert False, "Timed out waiting for pong"

    finally:
        print("[DEBUG] Cleaning up...")
        stack.stop()
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()
        if os.path.exists(bot_file):
            os.remove(bot_file)
