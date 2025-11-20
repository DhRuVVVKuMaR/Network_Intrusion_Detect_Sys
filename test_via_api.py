"""
Test script that injects packets via API (works without WinPcap)
This sends test packets directly to the running NIDS via HTTP API
"""

import requests
import time
import random

API_URL = "http://localhost:5000/api/inject_packet"


def inject_packet(protocol='TCP', src_ip='127.0.0.1', dst_ip='127.0.0.1', 
                 src_port=None, dst_port=None, payload=None, size=100):
    """Inject a packet via API"""
    try:
        data = {
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'size': size,
        }
        
        if src_port:
            data['src_port'] = src_port
        if dst_port:
            data['dst_port'] = dst_port
        if payload:
            if isinstance(payload, bytes):
                data['payload'] = payload.decode('utf-8', errors='ignore')
            else:
                data['payload'] = payload
        
        response = requests.post(API_URL, json=data, timeout=2)
        return response.status_code == 200
    except Exception as e:
        print(f"Error injecting packet: {e}")
        return False


def test_port_scan():
    """Test 1: Port Scanning"""
    print("\n[TEST 1] Port Scan Test (via API)...")
    print("This should trigger a PORT_SCAN alert (HIGH severity)")
    
    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5555, 6666, 6667, 31337]
    random_ports = [2000 + i for i in range(15)]  # 2000-2014
    all_ports = suspicious_ports + random_ports
    
    for port in all_ports:
        inject_packet(
            protocol='TCP',
            src_ip='192.168.1.100',  # Simulated attacker
            dst_ip='127.0.0.1',
            src_port=50000 + (port % 1000),
            dst_port=port
        )
        time.sleep(0.01)
    
    print(f"[TEST 1] Injected {len(all_ports)} port scan packets via API")


def test_suspicious_ports():
    """Test 2: Suspicious Ports"""
    print("\n[TEST 2] Suspicious Ports Test (via API)...")
    print("This should trigger SUSPICIOUS_PORT alerts (MEDIUM severity)")
    
    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5555, 6666, 31337]
    
    for port in suspicious_ports[:5]:
        inject_packet(
            protocol='TCP',
            src_ip='192.168.1.100',
            dst_ip='127.0.0.1',
            src_port=12345,
            dst_port=port
        )
        time.sleep(0.1)
    
    print(f"[TEST 2] Injected {len(suspicious_ports[:5])} suspicious port connections")


def test_suspicious_payload():
    """Test 3: Suspicious Payload Patterns"""
    print("\n[TEST 3] Suspicious Payload Test (via API)...")
    print("This should trigger SUSPICIOUS_PAYLOAD alerts (HIGH severity)")
    
    suspicious_patterns = [
        b"GET /etc/passwd",
        b"union select",
        b"<script>alert('xss')</script>",
        b"eval(base64_decode(",
        b"cmd.exe /c",
    ]
    
    for pattern in suspicious_patterns:
        inject_packet(
            protocol='TCP',
            src_ip='192.168.1.100',
            dst_ip='127.0.0.1',
            src_port=12345,
            dst_port=80,
            payload=pattern,
            size=len(pattern) + 40
        )
        time.sleep(0.2)
    
    print(f"[TEST 3] Injected {len(suspicious_patterns)} suspicious payloads")


def test_high_traffic_rate():
    """Test 4: High Traffic Rate"""
    print("\n[TEST 4] High Traffic Rate Test (via API)...")
    print("This should trigger ANOMALOUS_TRAFFIC_RATE alert (HIGH severity)")
    print("Sending rapid packets for 5 seconds...")
    
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < 5:
        inject_packet(
            protocol='TCP',
            src_ip='192.168.1.100',
            dst_ip='127.0.0.1',
            src_port=12345,
            dst_port=random.randint(8000, 9000)
        )
        packet_count += 1
        time.sleep(0.01)
    
    print(f"[TEST 4] Injected {packet_count} packets in 5 seconds ({packet_count/5:.1f} packets/sec)")


def test_connection_flood():
    """Test 5: Connection Flooding"""
    print("\n[TEST 5] Connection Flood Test (via API)...")
    print("This should trigger CONNECTION_FLOOD alert (HIGH severity)")
    
    for i in range(150):  # Exceed MAX_CONNECTIONS_PER_IP (100)
        inject_packet(
            protocol='TCP',
            src_ip='192.168.1.100',  # Same source IP
            dst_ip='127.0.0.1',
            src_port=50000 + (i % 1000),
            dst_port=7000 + (i % 100)
        )
        if i % 10 == 0:
            time.sleep(0.01)
    
    print(f"[TEST 5] Injected 150 connection attempts from same IP")


def test_anomalous_packet_size():
    """Test 6: Anomalous Packet Sizes"""
    print("\n[TEST 6] Anomalous Packet Size Test (via API)...")
    print("This should trigger ANOMALOUS_PACKET_SIZE alerts (MEDIUM severity)")
    
    # First inject some normal packets to establish baseline
    for i in range(50):
        inject_packet(
            protocol='TCP',
            src_ip='192.168.1.50',
            dst_ip='127.0.0.1',
            size=1500  # Normal size
        )
    
    # Now inject unusual sizes
    unusual_sizes = [10, 50, 100, 5000, 10000, 50000]
    
    for size in unusual_sizes:
        inject_packet(
            protocol='TCP',
            src_ip='192.168.1.100',
            dst_ip='127.0.0.1',
            size=size
        )
        time.sleep(0.1)
    
    print(f"[TEST 6] Injected packets with {len(unusual_sizes)} unusual sizes")


def run_all_tests():
    """Run all test scenarios"""
    print("=" * 60)
    print("NIDS Testing via API (Works without WinPcap!)")
    print("=" * 60)
    print(f"API URL: {API_URL}")
    print("Make sure NIDS is running and dashboard is accessible")
    print("=" * 60)
    
    # Check if API is accessible
    try:
        response = requests.get("http://localhost:5000/api/stats", timeout=2)
        if response.status_code != 200:
            print("ERROR: Cannot connect to NIDS API. Is the server running?")
            return
    except Exception as e:
        print(f"ERROR: Cannot connect to NIDS API: {e}")
        print("Make sure NIDS is running: python main.py")
        return
    
    print("[OK] Connected to NIDS API")
    time.sleep(2)
    
    tests = [
        ("Port Scan", test_port_scan),
        ("Suspicious Ports", test_suspicious_ports),
        ("Suspicious Payload", test_suspicious_payload),
        ("High Traffic Rate", test_high_traffic_rate),
        ("Connection Flood", test_connection_flood),
        ("Anomalous Packet Size", test_anomalous_packet_size),
    ]
    
    for test_name, test_func in tests:
        try:
            test_func()
            print(f"[OK] {test_name} test completed")
            time.sleep(2)
        except Exception as e:
            print(f"[FAIL] {test_name} test failed: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(1)
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)
    print("\nCheck your NIDS dashboard for alerts:")
    print("  - PORT_SCAN (HIGH)")
    print("  - SUSPICIOUS_PORT (MEDIUM)")
    print("  - SUSPICIOUS_PAYLOAD (HIGH)")
    print("  - ANOMALOUS_TRAFFIC_RATE (HIGH)")
    print("  - CONNECTION_FLOOD (HIGH)")
    print("  - ANOMALOUS_PACKET_SIZE (MEDIUM)")
    print("\nDashboard URL: http://localhost:5000")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()

