from typing import Callable, Optional, Union
from .messages import BinaryMessage, hash_id, MsgType, MessageFlags

DEBUG = False

def debug_print(msg: str, prefix: str = "DEBUG"):
    if DEBUG:
        print(f"[{prefix}] {msg}")

class ApplicationLayer:
    """
    Top layer: Command & Control interface.
    Handles BinaryMessages.
    """
    
    def __init__(self, node_id: str, debug: bool = False):
        self.node_id = node_id
        global DEBUG
        DEBUG = debug
        self.lower_layer = None
        self._receive_callback: Optional[Callable[[dict], None]] = None
        
        # Pre-compute my hash
        self.my_hash = hash_id(node_id)
    
    def set_lower_layer(self, layer):
        self.lower_layer = layer
    
    def on_receive(self, callback: Callable[[dict], None]):
        """Register callback for received messages."""
        self._receive_callback = callback
    
    def send(self, target: str, msg_type_str: str, **kwargs):
        """
        Send a message.
        Args:
            target: Target node ID or "ALL"
            msg_type_str: "command" or "response"
            kwargs: 
                - cmd: str (for command)
                - arg: str (for command)
                - output: str (for response)
        """
        if msg_type_str == "command":
            cmd = kwargs.get("cmd", "")
            arg = kwargs.get("arg", "")
            
            # Map cmd string to MsgType
            # TODO: Better mapping. For now hardcoded common ones.
            mtype = MsgType.UNKNOWN
            if cmd == "ping": mtype = MsgType.PING
            elif cmd == "w": mtype = MsgType.W
            elif cmd == "ls": mtype = MsgType.LS
            elif cmd == "id": mtype = MsgType.ID
            elif cmd == "copy": mtype = MsgType.COPY
            elif cmd == "exec": mtype = MsgType.EXEC
            
            payload = arg.encode('utf-8')
            flags = MessageFlags.REQUEST
            
        elif msg_type_str == "response":
            output = kwargs.get("output", "")
            mtype = MsgType.PING  # Default for text responses
            payload = output.encode('utf-8')
            flags = MessageFlags.RESPONSE
            
        elif msg_type_str == "file_response":
            # Binary file response: <filename_len:1><filename:N><file_data:rest>
            filename = kwargs.get("filename", "")
            file_data = kwargs.get("file_data", b"")
            mtype = MsgType.FILE_RESPONSE
            filename_bytes = filename.encode('utf-8')
            payload = bytes([len(filename_bytes)]) + filename_bytes + file_data
            flags = MessageFlags.RESPONSE
        else:
            return

        if target.startswith("HASH_"):
            # Target is already a hash string from receive_from_below
             try:
                 target_hash = int(target[5:], 16)
             except ValueError:
                 target_hash = hash_id(target)
        else:
            target_hash = hash_id(target)
            
        sender_hash = self.my_hash
        
        msg = BinaryMessage(target_hash, sender_hash, mtype, flags, payload)
        serialized = msg.serialize()
        
        if self.lower_layer:
            self.lower_layer.send_from_above(serialized)
    
    def receive_from_below(self, data: bytes):
        """Handle received bytes from transport layer."""
        try:
            # Try to deserialize as BinaryMessage
            msg = BinaryMessage.deserialize(data)
            if not msg:
                # Fallback: maybe it's raw JSON from legacy?
                # But TransportLayer should have given us bytes.
                return

            # Convert back to dict for generic callback handling (compatibility)
            # Or cleaner: callback receives object.
            # Keeping dict for compatibility with existing controller/bot logic
            
            # Map mtype to string cmd
            cmd_str = "unknown"
            if msg.msg_type == MsgType.PING: cmd_str = "ping"
            elif msg.msg_type == MsgType.W: cmd_str = "w"
            elif msg.msg_type == MsgType.LS: cmd_str = "ls"
            elif msg.msg_type == MsgType.ID: cmd_str = "id"
            elif msg.msg_type == MsgType.COPY: cmd_str = "copy"
            elif msg.msg_type == MsgType.EXEC: cmd_str = "exec"
            elif msg.msg_type == MsgType.FILE_RESPONSE: cmd_str = "file_response"
            
            # Decode target
            target_str = f"HASH_{msg.target_id_hash:04x}"
            if msg.target_id_hash == self.my_hash:
                target_str = "ME"
            elif msg.target_id_hash == hash_id("ALL"):
                target_str = "ALL"
            
            # Decode sender - try to reconstruct sensor_XXXX format
            def decode_node_id(node_hash: int) -> str:
                """Decode uint16 ID back to original format if possible."""
                if node_hash < 0xFFFF and node_hash != 0xFFFF:
                    return f"sensor_{node_hash}"
                elif node_hash == 0xFFFF:
                    return "ALL"
                else:
                    return f"HASH_{node_hash:04x}"
            
            sender_str = decode_node_id(msg.sender_id_hash)
            
            # Handle FILE_RESPONSE specially - extract binary data
            if msg.msg_type == MsgType.FILE_RESPONSE:
                # Payload format: <filename_len:1><filename:N><file_data:rest>
                if len(msg.payload) < 1:
                    return
                filename_len = msg.payload[0]
                if len(msg.payload) < 1 + filename_len:
                    return
                filename = msg.payload[1:1+filename_len].decode('utf-8', errors='ignore')
                file_data = msg.payload[1+filename_len:]
                
                parsed = {
                    "sender": sender_str,
                    "target": target_str,
                    "type": "file_response",
                    "filename": filename,
                    "file_data": file_data,  # Raw bytes!
                }
            else:
                parsed = {
                    "sender": sender_str,
                    "target": target_str,
                    "type": "response" if (msg.flags & MessageFlags.RESPONSE) else "command",
                    "cmd": cmd_str,
                    "arg": msg.payload.decode('utf-8', errors='ignore'),
                    "output": msg.payload.decode('utf-8', errors='ignore')
                }
            
            if self._receive_callback:
                self._receive_callback(parsed)
                
        except Exception as e:
            debug_print(f"App RX Error: {e}", "APP")
