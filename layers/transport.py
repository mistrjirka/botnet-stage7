import time
import zlib
import threading
import json
import base64
import random
from typing import Dict, Union, Optional
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .encryption import EncryptionLayer

DEBUG = False

def debug_print(msg: str, prefix: str = "DEBUG"):
    if DEBUG:
        print(f"[{prefix}] {msg}")

class TransportLayer:
    """
    Handles compression and packet splitting/reassembly.
    Uses binary chunk format: [msg_id:4][seq:2][total:2][data:N]
    """
    
    CHUNK_HEADER_SIZE = 8
    
    def __init__(self, node_id: str, debug: bool = False):
        self.node_id = node_id
        global DEBUG
        DEBUG = debug
        self.lower_layer = None
        self.upper_layer = None
        
        self._reassembly_buffer: Dict[int, dict] = {}
        self._buffer_lock = threading.Lock()
    
    def set_lower_layer(self, layer):
        self.lower_layer = layer
    
    def set_upper_layer(self, layer):
        self.upper_layer = layer
    
    def get_chunk_size(self) -> int:
        if not self.lower_layer:
            return 1024
        
        available = self.lower_layer.get_max_payload_size()
        chunk_size = available - self.CHUNK_HEADER_SIZE
        return max(chunk_size, 8)
    
    def _compress(self, data: bytes) -> bytes:
        compressed = zlib.compress(data, level=6)
        # Adaptive compression: if compressed is larger, send raw
        if len(compressed) >= len(data):
            return b'\x00' + data # 0x00 = Raw
        return b'\x01' + compressed # 0x01 = Compressed
    
    def _decompress(self, data: bytes) -> bytes:
        if not data:
            return b''
        flag = data[0]
        content = data[1:]
        if flag == 0x00:
            return content
        elif flag == 0x01:
            return zlib.decompress(content)
        else:
            # Fallback for legacy or error?
            try:
                # Maybe it's legacy zlib stream without flag? unlikely
                return zlib.decompress(data)
            except:
                return data
    
    def send_from_above(self, message: Union[dict, bytes]):
        """Compress, split into binary chunks, and send down."""
        
        if isinstance(message, dict):
            # Legacy JSON support
            payload = json.dumps(message).encode()
        else:
            payload = message
            
        compressed = self._compress(payload)
        chunk_size = self.get_chunk_size()
        msg_id = random.randint(0, 0xFFFFFFFF)
        
        chunks = [compressed[i:i+chunk_size] for i in range(0, len(compressed), chunk_size)]
        total = len(chunks)
        
        debug_print(f"TX: {len(payload)}B -> {len(compressed)}B compressed -> {total} chunks ({chunk_size}B each)", "TRANSPORT")
        
        for seq, chunk_data in enumerate(chunks):
            header = msg_id.to_bytes(4, 'big') + seq.to_bytes(2, 'big') + total.to_bytes(2, 'big')
            binary_chunk = header + chunk_data
            
            progress = f"[{seq+1}/{total}]"
            debug_print(f"TX chunk {progress} msg_id={msg_id:08x} ({len(binary_chunk)}B)", "TRANSPORT")
            
            if self.lower_layer:
                self.lower_layer.send_from_above(binary_chunk)
    
    def receive_from_below(self, payload: Union[dict, bytes]):
        if isinstance(payload, bytes):
             self._handle_binary_chunk_bytes(payload)
        elif "chunk" in payload: # Legacy JSON chunk
            # Not implementing full legacy JSON chunk receive if we focus on binary, 
            # but keeping structure if needed. For now assuming bytes.
            pass
        elif "msg_id" in payload: # Legacy JSON chunk
             pass
        else:
            # Pass up directly if not chunked (unlikely with this architecture)
            if self.upper_layer:
                self.upper_layer.receive_from_below(payload)
    
    def _handle_binary_chunk_bytes(self, binary_data: bytes):
        try:
            if len(binary_data) < self.CHUNK_HEADER_SIZE:
                return
            
            msg_id = int.from_bytes(binary_data[0:4], 'big')
            seq = int.from_bytes(binary_data[4:6], 'big')
            total = int.from_bytes(binary_data[6:8], 'big')
            chunk_data = binary_data[8:]
            
            debug_print(f"RX chunk [{seq+1}/{total}] msg_id={msg_id:08x}", "TRANSPORT")
            
            with self._buffer_lock:
                self._cleanup_old_entries()
                
                if msg_id not in self._reassembly_buffer:
                    self._reassembly_buffer[msg_id] = {
                        "chunks": {},
                        "total": total,
                        "timestamp": time.time()
                    }
                
                self._reassembly_buffer[msg_id]["chunks"][seq] = chunk_data
                
                entry = self._reassembly_buffer[msg_id]
                if len(entry["chunks"]) == entry["total"]:
                    debug_print(f"RX complete msg_id={msg_id:08x}", "TRANSPORT")
                    ordered_data = b"".join(entry["chunks"][i] for i in range(total))
                    del self._reassembly_buffer[msg_id]
                    
                    try:
                        decompressed = self._decompress(ordered_data)
                        if self.upper_layer:
                            self.upper_layer.receive_from_below(decompressed)
                    except Exception as e:
                        debug_print(f"RX decompress error: {e}", "TRANSPORT")
        except Exception as e:
            debug_print(f"RX chunk error: {e}", "TRANSPORT")

    def _cleanup_old_entries(self):
        now = time.time()
        timeout = 30
        expired = [msg for msg, entry in self._reassembly_buffer.items() if now - entry["timestamp"] > timeout]
        for msg in expired:
            del self._reassembly_buffer[msg]
