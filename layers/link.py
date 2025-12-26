import os
import time
import queue
import threading
import paho.mqtt.client as mqtt
from typing import Optional

# --- CONFIGURATION (from environment variables with defaults) ---
DEFAULT_BROKER = os.environ.get("MQTT_BROKER", "147.32.82.209")
DEFAULT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
DEFAULT_TOPIC = os.environ.get("MQTT_TOPIC", "sensors")
DEFAULT_SEND_INTERVAL = float(os.environ.get("SEND_INTERVAL", "1.0"))
DEFAULT_MAX_MQTT_PAYLOAD = int(os.environ.get("MAX_MQTT_PAYLOAD", "4096"))
DEFAULT_SALT = os.environ.get("ENCRYPTION_SALT", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")

DEBUG = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")

def debug_print(msg: str, prefix: str = "DEBUG"):
    if DEBUG:
        print(f"[{prefix}] {msg}")


class LinkLayer:
    """
    Bottom layer: Handles MQTT connection and timed packet sending.
    Sends one packet per interval, queues outgoing packets.
    """
    
    def __init__(self, node_id: str, broker: str = DEFAULT_BROKER, 
                 port: int = DEFAULT_PORT, topic: str = DEFAULT_TOPIC,
                 send_interval: float = DEFAULT_SEND_INTERVAL,
                 max_payload: int = DEFAULT_MAX_MQTT_PAYLOAD,
                 debug: bool = False):
        self.node_id = node_id
        self.broker = broker
        self.port = port
        self.topic = topic
        self.send_interval = send_interval
        self.max_payload = max_payload
        
        # Update global debug
        global DEBUG
        DEBUG = debug
        
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.outgoing_queue = queue.Queue()
        self.upper_layer = None
        self._running = False
        self._sender_thread = None
        
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
    
    def set_upper_layer(self, layer):
        self.upper_layer = layer
    
    def get_max_payload_size(self) -> int:
        return self.max_payload
    
    def _on_connect(self, client, userdata, flags, reason_code, properties):
        debug_print(f"MQTT Connected (code={reason_code})", "LINK")
        self.client.subscribe(self.topic)
        debug_print(f"MQTT Subscribed to {self.topic}", "LINK")
    
    def _on_message(self, client, userdata, msg):
        """Pass received raw packets up to encryption layer."""
        if self.upper_layer:
            try:
                self.upper_layer.receive_from_below(msg.payload)
            except Exception as e:
                debug_print(f"MQTT RX Error: {e}", "LINK")
    
    def send_to_wire(self, packet_bytes: bytes):
        """Queue a packet for sending."""
        qsize = self.outgoing_queue.qsize()
        if qsize > 10:
             debug_print(f"Queue backing up: {qsize} packets", "LINK")
        self.outgoing_queue.put(packet_bytes)
    
    def _sender_loop(self):
        """Background thread: send one packet per interval."""
        while self._running:
            try:
                try:
                    packet_bytes = self.outgoing_queue.get_nowait()
                    debug_print(f"MQTT TX: sending {len(packet_bytes)}B", "LINK")
                except queue.Empty:
                    # Request placeholder packet from encryption layer
                    if self.upper_layer:
                        packet_bytes = self.upper_layer.create_placeholder_packet()
                    else:
                        packet_bytes = None
                
                if packet_bytes:
                    self.client.publish(self.topic, packet_bytes)
            except Exception as e:
                debug_print(f"MQTT TX Error: {e}", "LINK")
            
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
