import os
from typing import Callable, Optional
from layers.link import LinkLayer
from layers.encryption import EncryptionLayer, StealthEncryptionLayer, deserialize_packet
from layers.transport import TransportLayer
from layers.application import ApplicationLayer

# Constants for ease of access if needed
DEFAULT_BROKER = "127.0.0.1"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "sensors"
DEFAULT_SALT = "S4ur0ns_S3cr3t_S4lt_2025"
DEFAULT_SEND_INTERVAL = 1.0
DEFAULT_MAX_MQTT_PAYLOAD = 4096

class ProtocolStack:
    """
    Complete protocol stack that wires all layers together.
    """
    
    def __init__(self, node_id: str, broker: str = DEFAULT_BROKER,
                 port: int = DEFAULT_PORT, topic: str = DEFAULT_TOPIC,
                 salt: str = DEFAULT_SALT, send_interval: float = DEFAULT_SEND_INTERVAL,
                 max_payload: int = DEFAULT_MAX_MQTT_PAYLOAD, debug: bool = False):
        self.node_id = node_id
        
        # Create layers
        self.link = LinkLayer(node_id, broker, port, topic, send_interval, max_payload, debug)
        self.encryption = EncryptionLayer(node_id, salt, debug)
        self.transport = TransportLayer(node_id, debug)
        self.application = ApplicationLayer(node_id, debug)
        
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
    
    def set_progress_callback(self, callback):
        """Set callback for TX/RX progress: cb(msg_id, seq, total, direction)."""
        self.transport.set_progress_callback(callback)


class StealthProtocolStack:
    """
    Protocol stack using steganographic float encoding.
    """
    
    def __init__(self, node_id: str, broker: str = DEFAULT_BROKER,
                 port: int = DEFAULT_PORT, topic: str = DEFAULT_TOPIC,
                 salt: str = DEFAULT_SALT, send_interval: float = DEFAULT_SEND_INTERVAL,
                 max_payload: int = DEFAULT_MAX_MQTT_PAYLOAD, debug: bool = False):
        self.node_id = node_id
        
        # Create layers
        self.link = LinkLayer(node_id, broker, port, topic, send_interval, max_payload, debug)
        self.encryption = StealthEncryptionLayer(node_id, salt, debug)
        self.transport = TransportLayer(node_id, debug)
        self.application = ApplicationLayer(node_id, debug)
        
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

    def set_progress_callback(self, callback):
        """Set callback for TX/RX progress: cb(msg_id, seq, total, direction)."""
        self.transport.set_progress_callback(callback)
