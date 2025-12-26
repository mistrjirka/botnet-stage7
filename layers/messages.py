import struct
import enum
import hashlib
from typing import Union, Optional

def encode_node_id(node_id: str) -> int:
    """Encode node ID to 2 bytes integer (uint16)."""
    if node_id == "ALL":
        return 0xFFFF
    
    # Try to parse numeric sensor ID
    if node_id.startswith("sensor_"):
        try:
            val = int(node_id.split("_")[1])
            if 0 <= val < 0xFFFF:
                return val
        except (ValueError, IndexError):
            pass
            
    # Fallback to hash (modulo 0xFFFE to reserve 0xFFFF for ALL)
    # Using CRC16 or simple modulo of MD5
    h = int.from_bytes(hashlib.md5(node_id.encode()).digest()[:2], 'big')
    # Reserve 0xFFFF
    if h == 0xFFFF:
        h = 0xFFFE
    return h

# Keep alias for compatibility during refactor if needed, but better replace.
hash_id = encode_node_id

class MsgType(enum.IntEnum):
    UNKNOWN = 0x00
    PING = 0x01
    W = 0x02
    LS = 0x03
    ID = 0x04
    COPY = 0x05
    EXEC = 0x06

class MessageFlags(enum.IntFlag):
    REQUEST = 0x00
    RESPONSE = 0x01
    ERROR = 0x02

class BinaryMessage:
    # Flags(1), Target(2), Sender(2), Type(1)
    HEADER_FORMAT = ">BHHB"
    HEADER_SIZE = 6
    
    def __init__(self, target_id_hash: int, sender_id_hash: int, msg_type: int, flags: int, payload: bytes):
        self.target_id_hash = target_id_hash
        self.sender_id_hash = sender_id_hash
        self.msg_type = msg_type
        self.flags = flags
        self.payload = payload

    def serialize(self) -> bytes:
        """Serialize message to bytes."""
        header = struct.pack(self.HEADER_FORMAT, self.flags, self.target_id_hash, self.sender_id_hash, self.msg_type)
        return header + self.payload
    
    @classmethod
    def deserialize(cls, data: bytes) -> Optional['BinaryMessage']:
        """Deserialize bytes to BinaryMessage."""
        if len(data) < cls.HEADER_SIZE:
             return None
        
        try:
            flags, target, sender, mtype = struct.unpack(cls.HEADER_FORMAT, data[:cls.HEADER_SIZE])
            payload = data[cls.HEADER_SIZE:]
            return cls(target, sender, mtype, flags, payload)
        except struct.error:
            return None

    def __repr__(self):
        return f"<BinaryMessage type={self.msg_type} flags={self.flags} len={len(self.payload)}>"
