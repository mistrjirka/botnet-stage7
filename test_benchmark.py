
import pytest
import time
import os
import sys
import subprocess
import shutil
import tempfile
import queue
import signal

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import ProtocolStack, StealthProtocolStack, DEFAULT_SALT

# Configuration
BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "sensors"
SALT = DEFAULT_SALT
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BOT_SCRIPT = os.path.join(SCRIPT_DIR, "bot.py")
VENV_PYTHON = os.path.join(SCRIPT_DIR, "venv", "bin", "python")
PYTHON_EXECUTABLE = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable

class BenchmarkClientHelper:
    """Helper for benchmark clients."""
    def __init__(self, mode="fingerprint"):
        self.mode = mode
        self.client_id = f"bench_controller_{mode}"
        self.responses = queue.Queue()
        self.discovered_bots = set()
        
        StackClass = StealthProtocolStack if mode == "stealth" else ProtocolStack
        self.stack = StackClass(
            node_id=self.client_id,
            broker=BROKER, 
            port=PORT, 
            topic=TOPIC, 
            salt=SALT,
            send_interval=1.0
        )
        self.stack.application.on_receive(self._on_message)
        self.my_sender_id = f"HASH_{self.stack.application.my_hash:04x}"
        self.stack.on_receive(self._on_message)

    def _on_message(self, message: dict):
        sender = message.get("sender", "")
        if sender == self.my_sender_id: return
        
        if (sender.startswith("sensor_") or sender.startswith("HASH_")):
            self.discovered_bots.add(sender)
            
        if message.get("type") in ("response", "file_response"):
            self.responses.put(message)

    def connect(self):
        self.stack.start()
        time.sleep(1)

    def disconnect(self):
        self.stack.stop()

    def send_command(self, target: str, cmd: str, arg: str = ""):
        self.stack.send(target, "command", cmd=cmd, arg=arg)

    def wait_for_response(self, timeout=10):
        try:
            return self.responses.get(timeout=timeout)
        except queue.Empty:
            return None
            
    def wait_for_responses(self, count, timeout=15):
        try:
            res = []
            deadline = time.time() + timeout
            while len(res) < count and time.time() < deadline:
                try:
                    res.append(self.responses.get(timeout=0.5))
                except queue.Empty: pass
            return res
        except: return []

    def clear_queues(self):
        while not self.responses.empty():
            try: self.responses.get_nowait()
            except: break

# Fixture to launch bots
@pytest.fixture(scope="module")
def benchmark_environment():
    """Launch 2 sets of bots (3 stealth, 3 fingerprint) or just one set per test class?
    Better to separate fixtures. But for simplicity let's manage processes manually in classes or specialized fixtures.
    """
    pass

@pytest.fixture(scope="class")
def stealth_bots():
    print("\n[SETUP] Launching Stealth Bots...")
    processes = []
    scripts = []
    with open(BOT_SCRIPT, 'r') as f: base_code = f.read()
    
    # Configure for stealth
    code = base_code.replace('BROKER = "147.32.82.209"', f'BROKER = "{BROKER}"')
    code = code.replace('USE_STEALTH_MODE = False', 'USE_STEALTH_MODE = True')
    # Force stealth env var just in case
    # Fast interval for benchmarks?
    code = code.replace('SEND_INTERVAL = 1.0', 'SEND_INTERVAL = 1.0')

    for i in range(3):
        path = os.path.join(SCRIPT_DIR, f"_bench_stealth_{i}.py")
        with open(path, 'w') as f: f.write(code)
        scripts.append(path)
        env = os.environ.copy()
        env["USE_STEALTH_MODE"] = "True"
        env["SEND_INTERVAL"] = "1.0"
        proc = subprocess.Popen([PYTHON_EXECUTABLE, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=SCRIPT_DIR)
        processes.append(proc)
        
    time.sleep(3)
    yield processes
    
    print("\n[TEARDOWN] Stopping Stealth Bots...")
    for p in processes: p.terminate()
    for s in scripts: 
        if os.path.exists(s): os.remove(s)

@pytest.fixture(scope="class")
def fingerprint_bots():
    print("\n[SETUP] Launching Fingerprint Bots...")
    processes = []
    scripts = []
    with open(BOT_SCRIPT, 'r') as f: base_code = f.read()
    
    # Configure for fingerprint
    code = base_code.replace('BROKER = "147.32.82.209"', f'BROKER = "{BROKER}"')
    code = code.replace('USE_STEALTH_MODE = True', 'USE_STEALTH_MODE = False')
    code = code.replace('SEND_INTERVAL = 1.0', 'SEND_INTERVAL = 1.0')
    
    for i in range(3):
        path = os.path.join(SCRIPT_DIR, f"_bench_finger_{i}.py")
        with open(path, 'w') as f: f.write(code)
        scripts.append(path)
        env = os.environ.copy()
        env["USE_STEALTH_MODE"] = "False"
        env["SEND_INTERVAL"] = "1.0"
        proc = subprocess.Popen([PYTHON_EXECUTABLE, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=SCRIPT_DIR)
        processes.append(proc)
        
    time.sleep(3)
    yield processes
    
    print("\n[TEARDOWN] Stopping Fingerprint Bots...")
    for p in processes: p.terminate()
    for s in scripts: 
        if os.path.exists(s): os.remove(s)

class TestStealthBenchmarks:
    @pytest.fixture(autouse=True)
    def client(self, stealth_bots):
        c = BenchmarkClientHelper("stealth")
        c.connect()
        # Wake up / Discover
        c.send_command("ALL", "ping")
        c.wait_for_responses(3, 10)
        c.clear_queues()
        yield c
        c.disconnect()

    def test_latency_ping(self, client):
        start = time.time()
        client.send_command("ALL", "ping")
        res = client.wait_for_responses(3, 30)
        duration = time.time() - start
        print(f"\n[BENCHMARK] Stealth Ping (3 bots): {duration:.4f}s")
        assert len(res) == 3

    def test_throughput_small_file(self, client):
        content = os.urandom(300) # 300 bytes random (incompressible)
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(content)
            tmp = f.name
        try:
            start = time.time()
            client.send_command("ALL", "copy", tmp)
            # Wait for 3 responses
            res = client.wait_for_responses(3, 60)
            duration = time.time() - start
            rate = 300 / duration if duration > 0 else 0
            
            print(f"\n[BENCHMARK] Stealth Copy (300B): {duration:.4f}s ({rate:.2f} B/s)")
            assert len(res) == 3
        finally:
            os.unlink(tmp)


class TestFingerprintBenchmarks:
    @pytest.fixture(autouse=True)
    def client(self, fingerprint_bots):
        c = BenchmarkClientHelper("fingerprint")
        c.connect()
        c.send_command("ALL", "ping")
        c.wait_for_responses(3, 5)
        c.clear_queues()
        yield c
        c.disconnect()

    def test_latency_ping(self, client):
        start = time.time()
        client.send_command("ALL", "ping")
        res = client.wait_for_responses(3, 10)
        duration = time.time() - start
        print(f"\n[BENCHMARK] Fingerprint Ping (3 bots): {duration:.4f}s")
        assert len(res) == 3

    def test_throughput_large_file(self, client):
        size = 50000
        content = os.urandom(size)
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(content)
            tmp = f.name
        try:
            start = time.time()
            client.send_command("ALL", "copy", tmp)
            res = client.wait_for_responses(3, 60)
            duration = time.time() - start
            rate = size / duration if duration > 0 else 0
            
            print(f"\n[BENCHMARK] Fingerprint Copy ({size}B): {duration:.4f}s ({rate:.2f} B/s)")
            assert len(res) == 3
        finally:
            os.unlink(tmp)

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
