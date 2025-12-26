#!/usr/bin/env python3
"""
Debug script to test bot+controller communication.
Run in 3 terminals:
  Terminal 1: python debug_bot.py bot
  Terminal 2: python debug_bot.py controller  
  Terminal 3: (watch output)
"""
import sys
import time
import json
from protocol import ProtocolStack

BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "sensors"
SALT = "S4ur0ns_S3cr3t_S4lt_2025"

def run_bot():
    print("[BOT] Starting...")
    
    received_count = [0]
    
    def handle_message(msg):
        received_count[0] += 1
        print(f"[BOT] Received #{received_count[0]}: {msg}")
        
        msg_type = msg.get("type")
        target = msg.get("target")
        sender = msg.get("sender")
        
        print(f"[BOT] type={msg_type}, target={target}, sender={sender}")
        
        if msg_type == "command" and (target == "ALL" or target == "sensor_debug"):
            print(f"[BOT] Processing command: {msg.get('cmd')}")
            stack.send(sender, "response", output="Pong from debug bot")
            print(f"[BOT] Sent response to {sender}")
    
    stack = ProtocolStack(
        node_id="sensor_debug",
        broker=BROKER,
        port=PORT,
        topic=TOPIC,
        salt=SALT,
        send_interval=0.5
    )
    stack.on_receive(handle_message)
    stack.start()
    
    print("[BOT] Running... (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stack.stop()
        print(f"\n[BOT] Stopped. Total received: {received_count[0]}")


def run_controller():
    print("[CTRL] Starting...")
    
    received_count = [0]
    
    def handle_message(msg):
        received_count[0] += 1
        print(f"[CTRL] Received #{received_count[0]}: {msg}")
    
    stack = ProtocolStack(
        node_id="controller_001",
        broker=BROKER,
        port=PORT,
        topic=TOPIC,
        salt=SALT,
        send_interval=0.5
    )
    stack.on_receive(handle_message)
    stack.start()
    
    print("[CTRL] Waiting 2s for bot to start...")
    time.sleep(2)
    
    print("[CTRL] Sending ping to ALL...")
    stack.send("ALL", "command", cmd="ping")
    
    print("[CTRL] Waiting for response...")
    for i in range(10):
        time.sleep(1)
        print(f"[CTRL] Waiting... ({i+1}s, received={received_count[0]})")
        if received_count[0] > 0:
            break
    
    stack.stop()
    print(f"[CTRL] Done. Total received: {received_count[0]}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_bot.py [bot|controller]")
        sys.exit(1)
    
    if sys.argv[1] == "bot":
        run_bot()
    elif sys.argv[1] == "controller":
        run_controller()
    else:
        print("Usage: python debug_bot.py [bot|controller]")
