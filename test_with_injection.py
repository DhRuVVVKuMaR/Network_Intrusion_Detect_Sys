"""
Test script that directly injects packets into NIDS detection system
This bypasses packet capture and works even without WinPcap/Npcap
"""

import sys
import time
import socket
from scapy.all import IP, TCP, UDP, Raw

# Add parent directory to path to import NIDS modules
sys.path.insert(0, '.')

from detection_engine import DetectionEngine
from alert_system import AlertSystem


def create_test_packet_info(protocol='TCP', src_ip='127.0.0.1', dst_ip='127.0.0.1', 
                            src_port=12345, dst_port=80, payload=None, size=100):
    """Create a test packet info dictionary"""
    return {
        'timestamp': time.time(),
        'size': size,
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'payload': payload.encode() if payload and isinstance(payload, str) else payload,
        'raw': None,
    }


def test_port_scan_injection(detection_engine):
    """Test 1: Port Scanning - Inject multiple port connections"""
    print("\n[TEST 1] Port Scan Test (Direct Injection)...")
    
    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5555, 6666, 6667, 31337]
    random_ports = [2000 + i for i in range(15)]  # 2000-2014
    all_ports = suspicious_ports + random_ports
    
    for port in all_ports:
        packet_info = create_test_packet_info(
            protocol='TCP',
            src_ip='192.168.1.100',  # Simulated attacker IP
            dst_ip='127.0.0.1',
            src_port=50000 + (port % 1000),
            dst_port=port
        )
        detection_engine.analyze_packet(packet_info)
        time.sleep(0.01)  # Small delay
    
    print(f"[TEST 1] Injected {len(all_ports)} port scan packets")
    time.sleep(1)


def test_suspicious_ports_injection(detection_engine):
    """Test 2: Suspicious Ports"""
    print("\n[TEST 2] Suspicious Ports Test (Direct Injection)...")
    
    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5555, 6666, 31337]
    
    for port in suspicious_ports[:5]:
        packet_info = create_test_packet_info(
            protocol='TCP',
            src_ip='192.168.1.100',
            dst_ip='127.0.0.1',
            src_port=12345,
            dst_port=port
        )
        detection_engine.analyze_packet(packet_info)
        time.sleep(0.1)
    
    print(f"[TEST 2] Injected {len(suspicious_ports[:5])} suspicious port connections")


def test_suspicious_payload_injection(detection_engine):
    """Test 3: Suspicious Payload Patterns"""
    print("\n[TEST 3] Suspicious Payload Test (Direct Injection)...")
    
    suspicious_patterns = [
        b"GET /etc/passwd",
        b"union select",
        b"<script>alert('xss')</script>",
        b"eval(base64_decode(",
        b"cmd.exe /c",
    ]
    
    for pattern in suspicious_patterns:
        packet_info = create_test_packet_info(
            protocol='TCP',
            src_ip='192.168.1.100',
            dst_ip='127.0.0.1',
            src_port=12345,
            dst_port=80,
            payload=pattern,
            size=len(pattern) + 40
        )
        detection_engine.analyze_packet(packet_info)
        time.sleep(0.2)
    
    print(f"[TEST 3] Injected {len(suspicious_patterns)} suspicious payloads")


def test_high_traffic_rate_injection(detection_engine):
    """Test 4: High Traffic Rate"""
    print("\n[TEST 4] High Traffic Rate Test (Direct Injection)...")
    print("Injecting rapid packets for 5 seconds...")
    
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < 5:
        packet_info = create_test_packet_info(
            protocol='TCP',
            src_ip='192.168.1.100',
            dst_ip='127.0.0.1',
            src_port=12345,
            dst_port=random.randint(8000, 9000)
        )
        detection_engine.analyze_packet(packet_info)
        packet_count += 1
        time.sleep(0.01)  # Very fast
    
    print(f"[TEST 4] Injected {packet_count} packets in 5 seconds ({packet_count/5:.1f} packets/sec)")


def test_connection_flood_injection(detection_engine):
    """Test 5: Connection Flooding"""
    print("\n[TEST 5] Connection Flood Test (Direct Injection)...")
    
    for i in range(150):  # Exceed MAX_CONNECTIONS_PER_IP (100)
        packet_info = create_test_packet_info(
            protocol='TCP',
            src_ip='192.168.1.100',  # Same source IP
            dst_ip='127.0.0.1',
            src_port=50000 + (i % 1000),
            dst_port=7000 + (i % 100)
        )
        detection_engine.analyze_packet(packet_info)
        if i % 10 == 0:
            time.sleep(0.01)
    
    print(f"[TEST 5] Injected 150 connection attempts from same IP")


def test_anomalous_packet_size_injection(detection_engine):
    """Test 6: Anomalous Packet Sizes"""
    print("\n[TEST 6] Anomalous Packet Size Test (Direct Injection)...")
    
    # First inject some normal packets to establish baseline
    for i in range(50):
        packet_info = create_test_packet_info(
            protocol='TCP',
            src_ip='192.168.1.50',
            dst_ip='127.0.0.1',
            size=1500  # Normal size
        )
        detection_engine.analyze_packet(packet_info)
    
    # Now inject unusual sizes
    unusual_sizes = [10, 50, 100, 5000, 10000, 50000]
    
    for size in unusual_sizes:
        packet_info = create_test_packet_info(
            protocol='TCP',
            src_ip='192.168.1.100',
            dst_ip='127.0.0.1',
            size=size
        )
        detection_engine.analyze_packet(packet_info)
        time.sleep(0.1)
    
    print(f"[TEST 6] Injected packets with {len(unusual_sizes)} unusual sizes")


def run_all_tests_with_injection():
    """Run all tests using direct packet injection"""
    print("=" * 60)
    print("NIDS Testing with Direct Packet Injection")
    print("=" * 60)
    print("This method bypasses packet capture and works without WinPcap")
    print("=" * 60)
    
    # Create detection engine and alert system
    alert_system = AlertSystem()
    detection_engine = DetectionEngine(alert_callback=alert_system.handle_alert)
    
    print("\nDetection engine initialized")
    print("Running tests...\n")
    
    tests = [
        ("Port Scan", test_port_scan_injection),
        ("Suspicious Ports", test_suspicious_ports_injection),
        ("Suspicious Payload", test_suspicious_payload_injection),
        ("High Traffic Rate", test_high_traffic_rate_injection),
        ("Connection Flood", test_connection_flood_injection),
        ("Anomalous Packet Size", test_anomalous_packet_size_injection),
    ]
    
    for test_name, test_func in tests:
        try:
            test_func(detection_engine)
            print(f"[OK] {test_name} test completed")
            time.sleep(2)
        except Exception as e:
            print(f"[FAIL] {test_name} test failed: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(1)
    
    print("\n" + "=" * 60)
    print("All injection tests completed!")
    print("=" * 60)
    
    # Print statistics
    stats = detection_engine.get_stats()
    alert_stats = alert_system.get_statistics()
    
    print(f"\nDetection Statistics:")
    print(f"  Total Alerts: {stats.get('total_alerts', 0)}")
    print(f"  Packets Analyzed: {stats.get('packets_analyzed', 0)}")
    print(f"\nAlert Breakdown:")
    for alert_type, count in alert_stats.get('by_type', {}).items():
        print(f"  {alert_type}: {count}")
    print(f"\nAlert Severity:")
    for severity, count in alert_stats.get('by_severity', {}).items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    print("\n" + "=" * 60)
    print("Check your NIDS dashboard - alerts should appear!")
    print("Dashboard URL: http://localhost:5000")
    print("=" * 60)


if __name__ == "__main__":
    import random
    run_all_tests_with_injection()

