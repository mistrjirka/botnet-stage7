import struct
import random
import hashlib
import json
from typing import Optional, Union
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .link import LinkLayer

# Config
DEFAULT_SALT = "S4ur0ns_S3cr3t_S4lt_2025"
DEBUG = False

def debug_print(msg: str, prefix: str = "DEBUG"):
    if DEBUG:
        print(f"[{prefix}] {msg}")

def serialize_packet(packet: dict) -> bytes:
    """Serialize packet dictionary to binary format (from protocol.py)."""
    data = bytearray()
    sensor_id = packet.get("sensor_id", "").encode('utf-8')
    data.extend(sensor_id + b'\0')
    fields = []
    
    for k, v in packet.items():
        if k == "sensor_id": continue
        if isinstance(v, bool):
             # Treating bool as int 0/1 usually works, or add 'b'. Let's stick to int if needed or just let it fall to int check if strictly python bool is int subclass.
             # Python bool IS int subclass. so isinstance(v, int) is true.
             # But let's be explicit if we want.
             fields.append((k,int(v), 'i'))
        elif isinstance(v, int):
            fields.append((k, v, 'i'))
        elif isinstance(v, float):
            fields.append((k, v, 'f'))
        elif isinstance(v, str):
            fields.append((k, v, 's'))
            
    data.append(len(fields))
    for name, val, ftype in fields:
        data.extend(name.encode('utf-8') + b'\0')
        if ftype == 'f':
            data.extend(b'f') # Type float
            data.extend(struct.pack('>d', val))
        elif ftype == 'i':
            data.extend(b'i') # Type int
            data.extend(struct.pack('>q', val))
        elif ftype == 's':
            data.extend(b's') # Type string
            s_bytes = val.encode('utf-8')
            data.extend(len(s_bytes).to_bytes(2, 'big'))
            data.extend(s_bytes)
    return bytes(data)

def deserialize_packet(data: bytes) -> dict:
    packet = {}
    offset = 0
    try:
        end = data.find(b'\0', offset)
        if end == -1: return {}
        packet["sensor_id"] = data[offset:end].decode('utf-8')
        offset = end + 1
        if offset >= len(data): return packet
        num_fields = data[offset]
        offset += 1
        for _ in range(num_fields):
            end = data.find(b'\0', offset)
            if end == -1: break
            name = data[offset:end].decode('utf-8')
            offset = end + 1
            
            if offset >= len(data): break
            ftype = chr(data[offset])
            offset += 1
            
            if ftype == 'f':
                if offset + 8 > len(data): break
                val = struct.unpack('>d', data[offset:offset+8])[0]
                packet[name] = val
                offset += 8
            elif ftype == 'i':
                if offset + 8 > len(data): break
                val = struct.unpack('>q', data[offset:offset+8])[0]
                packet[name] = val
                offset += 8
            elif ftype == 's':
                 if offset + 2 > len(data): break
                 slen = int.from_bytes(data[offset:offset+2], 'big')
                 offset += 2
                 if offset + slen > len(data): break
                 sval = data[offset:offset+slen].decode('utf-8')
                 packet[name] = sval
                 offset += slen
            
    except Exception as e:
        debug_print(f"Deserialization error: {e}", "PROTO")
        return {}
    return packet

class EncryptionLayer:
    STRUCTURE_OVERHEAD = 100
    AES_OVERHEAD = 32
    HEX_EXPANSION = 2
    
    def __init__(self, node_id: str, salt: str = DEFAULT_SALT, debug: bool = False):
        self.node_id = node_id
        self.salt = salt
        global DEBUG 
        DEBUG = debug
        self.lower_layer = None
        self.upper_layer = None
        self._last_sender = ""  # Stores sender from last received packet
    
    def set_lower_layer(self, layer):
        self.lower_layer = layer
    
    def set_upper_layer(self, layer):
        self.upper_layer = layer
    
    def get_max_payload_size(self) -> int:
        if not self.lower_layer:
            return 1024
        link_max = self.lower_layer.get_max_payload_size()
        available_hex = link_max - self.STRUCTURE_OVERHEAD
        available_encrypted = available_hex // self.HEX_EXPANSION
        available_plaintext = available_encrypted - self.AES_OVERHEAD
        return max(available_plaintext, 256)
    
    def _derive_key(self, data_dict: dict) -> bytes:
        raw_str = (self.salt + str(data_dict.get("sensor_id", "")) + 
                   str(data_dict.get("temp", "")) + 
                   str(data_dict.get("hum", "")) + 
                   str(data_dict.get("bat", "")))
        md5_hash = hashlib.md5(raw_str.encode()).digest()
        return md5_hash + md5_hash
    
    def _encrypt(self, plaintext: Union[str, bytes], key: bytes) -> str:
        """Encrypt data with AES-CBC and fixed-size output to prevent traffic analysis."""
        # Fixed fingerprint plaintext size (before AES padding): 256 bytes
        # This ensures all fingerprints are the same size regardless of payload
        FIXED_PLAINTEXT_SIZE = 256
        
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = plaintext.encode() if isinstance(plaintext, str) else plaintext
        
        # Add length prefix (2 bytes) + data + random padding to reach fixed size
        length_prefix = len(data).to_bytes(2, 'big')
        padded_data = length_prefix + data
        
        if len(padded_data) < FIXED_PLAINTEXT_SIZE:
            # Pad with random bytes to fixed size
            padding_needed = FIXED_PLAINTEXT_SIZE - len(padded_data)
            padded_data += get_random_bytes(padding_needed)
        elif len(padded_data) > FIXED_PLAINTEXT_SIZE:
            # Data too large - use as-is (will result in larger fingerprint for very large messages)
            pass
        
        ciphertext = cipher.encrypt(pad(padded_data, AES.block_size))
        return (iv + ciphertext).hex()
    
    def _decrypt(self, fingerprint_hex: str, key: bytes) -> Optional[bytes]:
        """Decrypt fingerprint and extract actual data (ignoring padding)."""
        try:
            encrypted_data = bytes.fromhex(fingerprint_hex)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            # Extract actual data using length prefix
            if len(decrypted) < 2:
                return None
            actual_length = int.from_bytes(decrypted[:2], 'big')
            if actual_length > len(decrypted) - 2:
                return None
            return decrypted[2:2+actual_length]
        except:
            return None
    
    def _create_sensor_data(self) -> dict:
        return {
            "sensor_id": self.node_id,
            "temp": round(random.uniform(20.0, 30.0), 1),
            "hum": round(random.uniform(40.0, 60.0), 1),
            "bat": random.randint(80, 100)
        }
    
    def create_placeholder_packet(self) -> bytes:
        packet = self._create_sensor_data()
        return serialize_packet(packet)
    
    def send_from_above(self, payload: Union[dict, bytes]):
        packet = self._create_sensor_data()
        key = self._derive_key(packet)
        
        if isinstance(payload, dict):
            # Legacy JSON support for transitions or if needed
            data = json.dumps(payload).encode()
            prefixed = b'\x00' + data
        else:
            # Binary payload
            prefixed = b'\x01' + payload
            
        packet["fingerprint"] = self._encrypt(prefixed, key)
        
        if self.lower_layer:
            self.lower_layer.send_to_wire(serialize_packet(packet))
    
    def receive_from_below(self, packet_bytes: bytes):
        packet = deserialize_packet(packet_bytes)
        if "fingerprint" not in packet:
            return
        
        # Store sender for upper layers to access
        self._last_sender = packet.get("sensor_id", "")
        
        key = self._derive_key(packet)
        decrypted = self._decrypt(packet["fingerprint"], key)
        
        if decrypted and self.upper_layer:
            try:
                type_byte = decrypted[0]
                content = decrypted[1:]
                
                if type_byte == 0:
                     payload = json.loads(content.decode())
                else:
                     payload = content 
                     
                self.upper_layer.receive_from_below(payload)
            except:
                pass

class StealthEncryptionLayer:
    SENSOR_FIELDS = [
        ("temp", 15.0, 35.0),
        ("hum", 30.0, 80.0),
        ("pres", 980.0, 1030.0),
        ("light", 0.0, 1000.0),
        ("co2", 400.0, 2000.0),
        ("noise", 20.0, 80.0),
        ("bat", 3.0, 4.2),        # Battery Voltage
        ("wifi", -90.0, -30.0),   # Signal Strength (dBm)
        ("pm25", 0.0, 500.0),     # PM2.5
        ("pm10", 0.0, 500.0),     # PM10
    ]
    BYTES_PER_FLOAT = 4
    MAX_PAYLOAD_SIZE = len(SENSOR_FIELDS) * BYTES_PER_FLOAT
    
    def __init__(self, node_id: str, salt: str = DEFAULT_SALT, debug: bool = False):
        self.node_id = node_id
        self.salt = salt
        global DEBUG
        DEBUG = debug
        self.lower_layer = None
        self.upper_layer = None
        self._xor_key = self._derive_xor_key()
        self._last_sender = ""  # Stores sender from last received packet
    
    def set_lower_layer(self, layer):
        self.lower_layer = layer
    
    def set_upper_layer(self, layer):
        self.upper_layer = layer
    
    def _derive_xor_key(self) -> bytes:
        return hashlib.sha256(self.salt.encode()).digest()
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        key = self._xor_key
        return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    
    def get_max_payload_size(self) -> int:
        return self.MAX_PAYLOAD_SIZE - 3  # Minus 2 bytes length + 1 byte type prefix
    
    def _encode_bytes_in_float(self, base_value: float, data_bytes: bytes) -> float:
        import struct
        float_bytes = struct.pack('>d', base_value)
        float_int = int.from_bytes(float_bytes, 'big')
        data_int = int.from_bytes(data_bytes.ljust(4, b'\x00')[:4], 'big')
        mask = 0xFFFFFFFF00000000
        float_int = (float_int & mask) | data_int
        result_bytes = float_int.to_bytes(8, 'big')
        return struct.unpack('>d', result_bytes)[0]
    
    def _decode_bytes_from_float(self, value: float) -> bytes:
        import struct
        float_bytes = struct.pack('>d', value)
        float_int = int.from_bytes(float_bytes, 'big')
        data_int = float_int & 0xFFFFFFFF
        return data_int.to_bytes(4, 'big')
    
    def _create_sensor_data_with_payload(self, payload_bytes: bytes) -> dict:
        packet = {"sensor_id": self.node_id}
        padded = payload_bytes.ljust(self.MAX_PAYLOAD_SIZE, b'\x00')
        for i, (name, min_val, max_val) in enumerate(self.SENSOR_FIELDS):
            base_value = random.uniform(min_val, max_val)
            start = i * self.BYTES_PER_FLOAT
            end = start + self.BYTES_PER_FLOAT
            field_bytes = padded[start:end]
            encoded_value = self._encode_bytes_in_float(base_value, field_bytes)
            packet[name] = encoded_value
        return packet
    
    def _extract_payload_from_packet(self, packet: dict) -> bytes:
        payload_bytes = b''
        for name, _, _ in self.SENSOR_FIELDS:
            if name in packet:
                value = packet[name]
                if isinstance(value, (int, float)):
                    payload_bytes += self._decode_bytes_from_float(float(value))
        return payload_bytes
    
    def create_placeholder_packet(self) -> bytes:
        packet = {"sensor_id": self.node_id}
        for name, min_val, max_val in self.SENSOR_FIELDS:
            packet[name] = round(random.uniform(min_val, max_val), 3)
        return serialize_packet(packet)
    
    def send_from_above(self, payload: Union[dict, bytes]):
        if isinstance(payload, dict):
            # JSON payload
            data = json.dumps(payload).encode()
            prefixed_payload = b'\x00' + data
        else:
            # Binary payload
            prefixed_payload = b'\x01' + payload
            
        length = len(prefixed_payload)
        prefixed = length.to_bytes(2, 'big') + prefixed_payload
        
        encrypted = self._xor_encrypt(prefixed)
        packet = self._create_sensor_data_with_payload(encrypted)
        
        debug_print(f"STEALTH TX: temp={packet['temp']:.3f} hum={packet['hum']:.3f}", "STEALTH")
        
        if self.lower_layer:
            self.lower_layer.send_to_wire(serialize_packet(packet))
    
    def receive_from_below(self, packet_bytes: bytes):
        packet = deserialize_packet(packet_bytes)
        
        if "fingerprint" in packet:
            return
        if not all(name in packet for name, _, _ in self.SENSOR_FIELDS):
            return
            
        is_placeholder = True
        for name, _, _ in self.SENSOR_FIELDS:
            val = packet.get(name, 0)
            if abs((val * 1000) - round(val * 1000)) > 1e-6:
                is_placeholder = False
                break
        
        if is_placeholder:
            return
        
        debug_print(f"STEALTH RX: temp={packet.get('temp', 0):.3f} hum={packet.get('hum', 0):.3f}", "STEALTH")
        
        # Store sender for upper layers to access
        self._last_sender = packet.get("sensor_id", "")
        
        try:
            encrypted = self._extract_payload_from_packet(packet)
            decrypted = self._xor_encrypt(encrypted)
            
            length = int.from_bytes(decrypted[:2], 'big')
            if length > len(decrypted) - 2:
                 debug_print(f"STEALTH RX: invalid length {length}", "STEALTH")
                 return
                 
            content = decrypted[2:2+length]
            type_byte = content[0]
            real_payload = content[1:]
            
            if type_byte == 0:
                final_payload = json.loads(real_payload.decode())
            else:
                final_payload = real_payload
            
            if self.upper_layer:
                self.upper_layer.receive_from_below(final_payload)
                
        except Exception as e:
            debug_print(f"Stealth RX Error: {e}", "STEALTH")
