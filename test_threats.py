"""
Test script to simulate various network threats for testing NIDS detection capabilities
Run this script while NIDS is running to test detection functionality
"""

import socket
import time
import threading
import random
import requests
from urllib.parse import quote

# Configuration
TARGET_HOST = "127.0.0.1"  # Localhost - change if testing against remote host
TEST_DURATION = 30  # seconds


def test_port_scan():
    """Test 1: Port Scanning - Should trigger PORT_SCAN alert"""
    print("\n[TEST 1] Starting Port Scan Test...")
    print("This should trigger a PORT_SCAN alert (HIGH severity)")
    
    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5555, 6666, 6667, 31337]
    # Add more random ports to exceed threshold
    random_ports = [random.randint(1000, 65535) for _ in range(15)]
    all_ports = suspicious_ports + random_ports
    
    for port in all_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((TARGET_HOST, port))
            sock.close()
            time.sleep(0.05)  # Small delay between attempts
        except:
            pass
    
    print(f"[TEST 1] Scanned {len(all_ports)} ports - Check dashboard for PORT_SCAN alert")


def test_suspicious_ports():
    """Test 2: Connection to Suspicious Ports - Should trigger SUSPICIOUS_PORT alert"""
    print("\n[TEST 2] Starting Suspicious Port Test...")
    print("This should trigger SUSPICIOUS_PORT alerts (MEDIUM severity)")
    
    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5555, 6666, 31337]
    
    for port in suspicious_ports[:5]:  # Test first 5 ports
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect_ex((TARGET_HOST, port))
            sock.close()
            time.sleep(0.2)
        except:
            pass
    
    print(f"[TEST 2] Attempted connections to {len(suspicious_ports[:5])} suspicious ports")


def test_suspicious_payload():
    """Test 3: Suspicious Payload Patterns - Should trigger SUSPICIOUS_PAYLOAD alert"""
    print("\n[TEST 3] Starting Suspicious Payload Test...")
    print("This should trigger SUSPICIOUS_PAYLOAD alerts (HIGH severity)")
    
    suspicious_patterns = [
        b"GET /etc/passwd",
        b"union select",
        b"<script>alert('xss')</script>",
        b"eval(base64_decode(",
        b"cmd.exe /c",
    ]
    
    # Try to send suspicious payloads via HTTP requests
    for pattern in suspicious_patterns:
        try:
            # Encode pattern for URL
            encoded = quote(pattern)
            url = f"http://{TARGET_HOST}:5000/?test={encoded}"
            requests.get(url, timeout=1)
            time.sleep(0.3)
        except:
            # If HTTP fails, try raw socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((TARGET_HOST, 80))
                sock.send(b"GET /?" + pattern + b" HTTP/1.1\r\nHost: " + TARGET_HOST.encode() + b"\r\n\r\n")
                sock.close()
                time.sleep(0.3)
            except:
                pass
    
    print(f"[TEST 3] Sent {len(suspicious_patterns)} suspicious payloads")


def test_high_traffic_rate():
    """Test 4: High Traffic Rate - Should trigger ANOMALOUS_TRAFFIC_RATE alert"""
    print("\n[TEST 4] Starting High Traffic Rate Test...")
    print("This should trigger ANOMALOUS_TRAFFIC_RATE alert (HIGH severity)")
    print("Sending rapid packets for 10 seconds...")
    
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < 10:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            port = random.randint(8000, 9000)
            sock.connect_ex((TARGET_HOST, port))
            sock.close()
            packet_count += 1
            time.sleep(0.01)  # Very small delay = high rate
        except:
            pass
    
    print(f"[TEST 4] Sent {packet_count} packets in 10 seconds ({packet_count/10:.1f} packets/sec)")


def test_connection_flood():
    """Test 5: Connection Flooding - Should trigger CONNECTION_FLOOD alert"""
    print("\n[TEST 5] Starting Connection Flood Test...")
    print("This should trigger CONNECTION_FLOOD alert (HIGH severity)")
    
    def make_connection():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            port = random.randint(7000, 8000)
            sock.connect_ex((TARGET_HOST, port))
            sock.close()
        except:
            pass
    
    # Create many connections rapidly
    threads = []
    for i in range(150):  # Exceed MAX_CONNECTIONS_PER_IP (100)
        t = threading.Thread(target=make_connection)
        threads.append(t)
        t.start()
        time.sleep(0.01)
    
    # Wait for all threads
    for t in threads:
        t.join(timeout=1)
    
    print(f"[TEST 5] Created {len(threads)} connections rapidly")


def test_anomalous_packet_size():
    """Test 6: Anomalous Packet Sizes - Should trigger ANOMALOUS_PACKET_SIZE alert"""
    print("\n[TEST 6] Starting Anomalous Packet Size Test...")
    print("This should trigger ANOMALOUS_PACKET_SIZE alerts (MEDIUM severity)")
    
    # Send packets with unusual sizes
    unusual_sizes = [10, 50, 100, 5000, 10000, 50000]  # Very small and very large
    
    for size in unusual_sizes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect_ex((TARGET_HOST, random.randint(6000, 7000)))
            # Send data of unusual size
            data = b"X" * min(size, 65535)  # Limit to max TCP payload
            sock.send(data)
            sock.close()
            time.sleep(0.2)
        except:
            pass
    
    print(f"[TEST 6] Sent packets with {len(unusual_sizes)} different unusual sizes")


def test_mixed_attack():
    """Test 7: Mixed Attack Pattern - Multiple threat types"""
    print("\n[TEST 7] Starting Mixed Attack Test...")
    print("This should trigger multiple types of alerts")
    
    # Port scan
    for port in range(2000, 2010):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((TARGET_HOST, port))
            sock.close()
        except:
            pass
        time.sleep(0.05)
    
    # Suspicious port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect_ex((TARGET_HOST, 4444))  # Metasploit port
        sock.close()
    except:
        pass
    
    # Suspicious payload
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((TARGET_HOST, 80))
        sock.send(b"GET /?cmd=whoami HTTP/1.1\r\nHost: " + TARGET_HOST.encode() + b"\r\n\r\n")
        sock.close()
    except:
        pass
    
    print("[TEST 7] Mixed attack pattern completed")


def run_all_tests():
    """Run all test scenarios"""
    print("=" * 60)
    print("NIDS Threat Testing Suite")
    print("=" * 60)
    print(f"Target Host: {TARGET_HOST}")
    print(f"Make sure NIDS is running and monitoring network traffic")
    print("=" * 60)
    
    time.sleep(2)  # Give user time to read
    
    tests = [
        ("Port Scan", test_port_scan),
        ("Suspicious Ports", test_suspicious_ports),
        ("Suspicious Payload", test_suspicious_payload),
        ("High Traffic Rate", test_high_traffic_rate),
        ("Connection Flood", test_connection_flood),
        ("Anomalous Packet Size", test_anomalous_packet_size),
        ("Mixed Attack", test_mixed_attack),
    ]
    
    for test_name, test_func in tests:
        try:
            test_func()
            print(f"[OK] {test_name} test completed")
            time.sleep(2)  # Wait between tests
        except Exception as e:
            print(f"[FAIL] {test_name} test failed: {e}")
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


def run_interactive_menu():
    """Interactive menu to run individual tests"""
    tests = {
        '1': ('Port Scan', test_port_scan),
        '2': ('Suspicious Ports', test_suspicious_ports),
        '3': ('Suspicious Payload', test_suspicious_payload),
        '4': ('High Traffic Rate', test_high_traffic_rate),
        '5': ('Connection Flood', test_connection_flood),
        '6': ('Anomalous Packet Size', test_anomalous_packet_size),
        '7': ('Mixed Attack', test_mixed_attack),
        '8': ('Run All Tests', run_all_tests),
    }
    
    while True:
        print("\n" + "=" * 60)
        print("NIDS Threat Testing Menu")
        print("=" * 60)
        for key, (name, _) in tests.items():
            print(f"{key}. {name}")
        print("0. Exit")
        print("=" * 60)
        
        choice = input("\nSelect test to run: ").strip()
        
        if choice == '0':
            print("Exiting...")
            break
        elif choice in tests:
            name, func = tests[choice]
            print(f"\nRunning: {name}")
            try:
                func()
                print(f"✓ {name} completed")
            except Exception as e:
                print(f"✗ {name} failed: {e}")
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        run_all_tests()
    else:
        run_interactive_menu()

