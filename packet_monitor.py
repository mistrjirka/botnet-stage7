import paho.mqtt.client as mqtt
import os
import time
import datetime
from layers.encryption import deserialize_packet

# --- CONFIGURATION ---
BROKER = "147.32.82.209"
PORT = 1883
TOPIC = "sensors"

def on_connect(client, userdata, flags, reason_code, properties):
    print(f"[*] Connected to MQTT Broker {BROKER}:{PORT}")
    client.subscribe(TOPIC)
    print(f"[*] Subscribed to topic: {TOPIC}")

def on_message(client, userdata, msg):
    try:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        payload_len = len(msg.payload)
        
        # Try to deserialize
        data = deserialize_packet(msg.payload)
        
        if not data:
            print(f"[{timestamp}] Raw ({payload_len} bytes): {msg.payload[:50]}...")
            return

        sensor_id = data.get("sensor_id", "UNKNOWN")
        
        # Format the output
        output = f"[{timestamp}] {sensor_id:<15} | Size: {payload_len:<4} | "
        
        # Add sensor readings if present
        readings = []
        for key, val in data.items():
            if key == "sensor_id": continue
            if key == "fingerprint":
                readings.append(f"fingerprint={val[:10]}...")
            elif isinstance(val, float):
                readings.append(f"{key}={val:.2f}")
            else:
                readings.append(f"{key}={val}")
        
        output += ", ".join(readings)
        print(output)
        
    except Exception as e:
        print(f"[!] Error parsing packet: {e}")

def main():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        print(f"[*] Starting Packet Monitor...")
        client.connect(BROKER, PORT, 60)
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Packet Monitor")
        client.disconnect()
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
