# Network Intrusion Detection System - Function Flow Timeline

This document outlines the complete code flow and function execution timeline of the NIDS project.

## 🚀 Execution Flow Timeline

### **Phase 1: Initialization (Startup)**

```
1. main.py::main()
   └─> Registers signal handlers (SIGINT, SIGTERM)
   └─> Checks for admin/root privileges
   └─> Creates NIDS instance
       └─> NIDS.__init__()
           ├─> AlertSystem.__init__()
           │   └─> AlertSystem.setup_logging()
           │       ├─> Creates RotatingFileHandler for nids.log
           │       └─> Configures console handler
           │
           ├─> DetectionEngine.__init__(alert_callback)
           │   ├─> SignatureDetector.__init__()
           │   │   └─> PortScanDetector.__init__()
           │   │       └─> Initializes scan_attempts dict
           │   │
           │   └─> AnomalyDetector.__init__() [if enabled]
           │       └─> Initializes packet_sizes, packet_rates, stats
           │
           └─> PacketCapture.__init__(interface, packet_callback)
               └─> PacketCapture._detect_interface()
                   └─> Scans available interfaces
                   └─> Returns best interface (Ethernet preferred)
```

### **Phase 2: System Start**

```
2. NIDS.start()
   ├─> Logs system configuration
   │
   ├─> PacketCapture.start_capture()
   │   ├─> Sets is_capturing = True
   │   ├─> Records start_time
   │   └─> Starts capture_thread (daemon)
   │       └─> capture_loop()
   │           └─> sniff() [Scapy function]
   │               └─> Continuously captures packets
   │
   ├─> dashboard.init_dashboard()
   │   └─> Stores global references to NIDS components
   │
   └─> Starts dashboard_thread (daemon)
       └─> dashboard.run_dashboard()
           ├─> start_dashboard_update_thread()
           │   └─> update_loop() [runs every 2 seconds]
           │       ├─> Collects stats from all components
           │       └─> Emits WebSocket updates
           │
           └─> socketio.run() [Flask-SocketIO server]
               └─> Web dashboard available at http://localhost:5000
```

### **Phase 3: Packet Processing Loop (Continuous)**

```
3. For each captured packet:

   PacketCapture._process_packet(packet)
   ├─> Increments stats['total_packets']
   ├─> Extracts packet information:
   │   ├─> timestamp, size, protocol
   │   ├─> src_ip, dst_ip, src_port, dst_port
   │   └─> payload (if Raw layer exists)
   │
   ├─> Parses protocol layers:
   │   ├─> IP layer → IPv4 packet
   │   │   ├─> TCP → TCP packet
   │   │   ├─> UDP → UDP packet
   │   │   └─> ICMP → ICMP packet
   │   └─> IPv6 layer → IPv6 packet
   │
   ├─> Updates statistics:
   │   ├─> Protocol counters (TCP/UDP/ICMP/IPv6)
   │   ├─> bytes_captured
   │   └─> connection_tracker
   │
   └─> Calls packet_callback (DetectionEngine.analyze_packet)
       │
       └─> DetectionEngine.analyze_packet(packet_info)
           ├─> Appends to packet_history (deque, maxlen=10000)
           │
           ├─> SIGNATURE DETECTION (if enabled):
           │   └─> SignatureDetector.check_packet(packet_info)
           │       ├─> Checks suspicious ports
           │       │   └─> If match → Creates SUSPICIOUS_PORT alert
           │       │
           │       ├─> Checks suspicious payload patterns
           │       │   └─> If match → Creates SUSPICIOUS_PAYLOAD alert
           │       │
           │       └─> PortScanDetector.check_packet(packet_info)
           │           ├─> Tracks unique ports per source IP
           │           ├─> Checks if threshold exceeded (10 ports in 60s)
           │           └─> If exceeded → Creates PORT_SCAN alert
           │
           └─> ANOMALY DETECTION (if enabled, every 100 packets):
               ├─> AnomalyDetector.update_stats(packet_info)
               │   ├─> Updates packet_sizes deque
               │   ├─> Updates packet_rates per source IP
               │   ├─> Updates connection_counts
               │   └─> Calculates baseline (mean, std) after 100 packets
               │
               └─> AnomalyDetector.check_anomalies() [every 100 packets]
                   ├─> Checks anomalous packet sizes (z-score > 2.5)
                   │   └─> Creates ANOMALOUS_PACKET_SIZE alert
                   │
                   ├─> Checks anomalous traffic rates (3x average)
                   │   └─> Creates ANOMALOUS_TRAFFIC_RATE alert
                   │
                   └─> Checks connection flooding (>100 per IP)
                       └─> Creates CONNECTION_FLOOD alert
```

### **Phase 4: Alert Handling**

```
4. For each detected alert:

   DetectionEngine._handle_alert(alert)
   ├─> Increments total_alerts
   ├─> Updates alerts_by_type counter
   ├─> Logs alert with WARNING level
   └─> Calls alert_callback (AlertSystem.handle_alert)
       │
       └─> AlertSystem.handle_alert(alert)
           ├─> Formats timestamp
           ├─> Appends to alerts deque (maxlen=1000)
           │
           ├─> Logs alert to file and console:
           │   ├─> HIGH/CRITICAL → logger.critical()
           │   ├─> MEDIUM → logger.warning()
           │   └─> LOW → logger.info()
           │
           ├─> AlertSystem._print_alert(alert)
           │   └─> Prints colored alert to console
           │
           └─> AlertSystem._send_email_alert(alert) [if enabled & HIGH/CRITICAL]
               └─> Sends email via SMTP
```

### **Phase 5: Dashboard Updates (Every 2 seconds)**

```
5. Dashboard Update Loop:

   dashboard.update_loop()
   ├─> Collects statistics:
   │   ├─> PacketCapture.get_stats()
   │   │   ├─> Calculates runtime
   │   │   ├─> Calculates packets_per_second
   │   │   └─> Returns capture statistics
   │   │
   │   ├─> DetectionEngine.get_stats()
   │   │   ├─> Returns total_alerts, alerts_by_type
   │   │   └─> Returns anomaly_stats (if enabled)
   │   │
   │   └─> AlertSystem.get_statistics()
   │       ├─> Counts alerts by type and severity
   │       └─> Returns statistics dictionary
   │
   └─> Emits WebSocket events:
       ├─> 'stats_update' → Sends all statistics
       └─> 'new_alerts' → Sends recent 10 alerts
```

### **Phase 6: API Endpoints (On-Demand)**

```
6. Web Dashboard API Calls:

   GET /api/stats
   └─> dashboard.get_stats()
       └─> Returns JSON with all statistics

   GET /api/alerts
   └─> dashboard.get_alerts()
       └─> AlertSystem.get_recent_alerts(100)
           └─> Returns last 100 alerts

   GET /api/connections
   └─> dashboard.get_connections()
       └─> PacketCapture.get_connection_stats()
           └─> Returns connection_tracker dictionary
```

### **Phase 7: Statistics Display (Every 30 seconds)**

```
7. Console Statistics:

   NIDS.print_stats() [called every 30 seconds]
   ├─> PacketCapture.get_stats()
   ├─> DetectionEngine.get_stats()
   ├─> AlertSystem.get_statistics()
   └─> Prints formatted statistics to console
```

### **Phase 8: Shutdown**

```
8. System Shutdown (Ctrl+C or SIGTERM):

   signal_handler(sig, frame)
   └─> NIDS.stop()
       ├─> Sets running = False
       ├─> PacketCapture.stop_capture()
       │   ├─> Sets is_capturing = False
       │   └─> Joins capture_thread (timeout=5s)
       └─> Logs shutdown message
```

## 📊 Function Call Hierarchy

```
main()
├─> NIDS.__init__()
│   ├─> AlertSystem.__init__()
│   │   └─> AlertSystem.setup_logging()
│   ├─> DetectionEngine.__init__()
│   │   ├─> SignatureDetector.__init__()
│   │   │   └─> PortScanDetector.__init__()
│   │   └─> AnomalyDetector.__init__()
│   └─> PacketCapture.__init__()
│       └─> PacketCapture._detect_interface()
│
└─> NIDS.start()
    ├─> PacketCapture.start_capture()
    │   └─> capture_loop() [thread]
    │       └─> sniff() → _process_packet() [per packet]
    │           └─> DetectionEngine.analyze_packet()
    │               ├─> SignatureDetector.check_packet()
    │               │   └─> PortScanDetector.check_packet()
    │               └─> AnomalyDetector.update_stats()
    │               └─> AnomalyDetector.check_anomalies() [every 100 packets]
    │                   └─> DetectionEngine._handle_alert()
    │                       └─> AlertSystem.handle_alert()
    │                           ├─> AlertSystem._print_alert()
    │                           └─> AlertSystem._send_email_alert() [if enabled]
    │
    ├─> init_dashboard()
    └─> run_dashboard() [thread]
        └─> update_loop() [thread, every 2s]
            ├─> PacketCapture.get_stats()
            ├─> DetectionEngine.get_stats()
            └─> AlertSystem.get_statistics()
```

## 🔄 Continuous Operations

1. **Packet Capture**: Runs continuously in background thread
2. **Packet Processing**: Synchronous, called for each packet
3. **Signature Detection**: Synchronous, called for each packet
4. **Anomaly Detection**: Runs every 100 packets
5. **Dashboard Updates**: Runs every 2 seconds
6. **Statistics Display**: Runs every 30 seconds
7. **Alert Handling**: Asynchronous, triggered by detections

## 📝 Key Data Structures

- `packet_history`: deque(maxlen=10000) - Recent packet metadata
- `alerts`: deque(maxlen=1000) - Recent alerts
- `connection_tracker`: defaultdict - Connection statistics
- `scan_attempts`: defaultdict - Port scan tracking
- `packet_sizes`: deque(maxlen=10000) - Packet size history
- `packet_rates`: defaultdict(deque) - Per-IP packet timestamps




