#!/usr/bin/env python3
"""
Debug script to test stealth encoding in isolation.
Run two terminals:
  Terminal 1: python debug_stealth.py receiver
  Terminal 2: python debug_stealth.py sender
"""
import sys
import time
import json
import paho.mqtt.client as mqtt
from protocol import StealthEncryptionLayer, DEFAULT_SALT

BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "stealth_test"

def test_encode_decode_locally():
    """Test encoding/decoding without MQTT."""
    print("=== LOCAL ENCODING TEST ===")
    
    layer = StealthEncryptionLayer(node_id="test", salt=DEFAULT_SALT)
    
    # Test 1: Simple bytes
    original = b"HELLO"
    print(f"Original: {original}")
    
    encrypted = layer._xor_encrypt(original)
    print(f"Encrypted: {encrypted.hex()}")
    
    # Create packet
    packet = layer._create_sensor_data_with_payload(encrypted)
    print(f"Packet: {json.dumps(packet, indent=2)}")
    
    # Extract
    extracted = layer._extract_payload_from_packet(packet)
    print(f"Extracted (raw): {extracted.hex()}")
    
    # Decrypt
    decrypted = layer._xor_encrypt(extracted[:len(encrypted)])
    print(f"Decrypted: {decrypted}")
    
    if decrypted == original:
        print("SUCCESS: Local roundtrip works!")
    else:
        print("FAILED: Roundtrip mismatch")
    
    return packet


def run_receiver():
    """Receive and decode stealth packets."""
    print("=== STEALTH RECEIVER ===")
    
    layer = StealthEncryptionLayer(node_id="receiver", salt=DEFAULT_SALT)
    
    def on_message(client, userdata, msg):
        try:
            packet = json.loads(msg.payload.decode())
            print(f"\nReceived packet:")
            print(f"  sensor_id: {packet.get('sensor_id')}")
            print(f"  temp: {packet.get('temp')}")
            print(f"  hum: {packet.get('hum')}")
            
            # Check if it has stealth fields
            if all(name in packet for name, _, _ in layer.SENSOR_FIELDS):
                print("  Has all stealth fields!")
                
                # Extract payload
                extracted = layer._extract_payload_from_packet(packet)
                print(f"  Extracted bytes: {extracted[:20].hex()}...")
                
                # Try to decrypt
                decrypted = layer._xor_encrypt(extracted)
                print(f"  Decrypted first 20: {decrypted[:20]}")
                
                # Check for length prefix
                length = int.from_bytes(decrypted[:2], 'big')
                print(f"  Length prefix: {length}")
                
                if 0 < length <= 22:
                    payload = decrypted[2:2+length]
                    print(f"  Payload: {payload}")
                    try:
                        msg_dict = json.loads(payload.decode())
                        print(f"  Decoded JSON: {msg_dict}")
                    except:
                        print(f"  (Not valid JSON)")
            else:
                print("  Missing stealth fields")
                
        except Exception as e:
            print(f"Error: {e}")
    
    def on_connect(client, userdata, flags, reason_code, properties):
        print(f"Connected! Subscribing to {TOPIC}")
        client.subscribe(TOPIC)
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT, 60)
    
    print("Listening for stealth packets...")
    client.loop_forever()


def run_sender():
    """Send a simple stealth packet."""
    print("=== STEALTH SENDER ===")
    
    layer = StealthEncryptionLayer(node_id="sender", salt=DEFAULT_SALT)
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(BROKER, PORT, 60)
    client.loop_start()
    
    # Create a simple message
    message = {"msg": "Hi"}  # Very short!
    print(f"Message: {message}")
    
    # Serialize
    payload_json = json.dumps(message)
    payload_bytes = payload_json.encode()
    print(f"Payload bytes ({len(payload_bytes)}): {payload_bytes}")
    
    # Add length prefix
    length = len(payload_bytes)
    prefixed = length.to_bytes(2, 'big') + payload_bytes
    print(f"With prefix ({len(prefixed)}): {prefixed.hex()}")
    
    # Encrypt
    encrypted = layer._xor_encrypt(prefixed)
    print(f"Encrypted: {encrypted.hex()}")
    
    # Create packet
    packet = layer._create_sensor_data_with_payload(encrypted)
    print(f"\nPacket:")
    for key, val in packet.items():
        print(f"  {key}: {val}")
    
    # Send
    payload_str = json.dumps(packet)
    print(f"\nSending ({len(payload_str)} bytes)...")
    client.publish(TOPIC, payload_str)
    
    time.sleep(1)
    client.loop_stop()
    print("Sent!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Testing local encoding first...")
        test_encode_decode_locally()
        print("\nUsage: python debug_stealth.py [receiver|sender]")
    elif sys.argv[1] == "receiver":
        run_receiver()
    elif sys.argv[1] == "sender":
        run_sender()
    else:
        print("Usage: python debug_stealth.py [receiver|sender]")
