
import time
import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
import numpy as np
from datetime import datetime, timedelta
import config

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Main detection engine for network intrusion detection"""
    
    def __init__(self, alert_callback: Optional[callable] = None):
        """
        Initialize detection engine
        
        Args:
            alert_callback: Function to call when an alert is generated
        """
        self.alert_callback = alert_callback
        self.signature_detector = SignatureDetector(alert_callback)
        self.anomaly_detector = AnomalyDetector(alert_callback) if config.ANOMALY_DETECTION_ENABLED else None
        
        # Statistics
        self.total_alerts = 0
        self.alerts_by_type = defaultdict(int)
        self.packet_history = deque(maxlen=10000)
        
    def analyze_packet(self, packet_info: Dict[str, Any]):
        """
        Analyze a packet for threats
        
        Args:
            packet_info: Packet information dictionary
        """
        self.packet_history.append({
            'timestamp': packet_info['timestamp'],
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'protocol': packet_info.get('protocol'),
            'size': packet_info.get('size', 0),
        })
        
        # Signature-based detection
        if config.SIGNATURE_DETECTION_ENABLED:
            alerts = self.signature_detector.check_packet(packet_info)
            for alert in alerts:
                self._handle_alert(alert)
        
        # Anomaly detection (runs periodically)
        if self.anomaly_detector and len(self.packet_history) >= config.MIN_PACKETS_FOR_ANALYSIS:
            self.anomaly_detector.update_stats(packet_info)
            if len(self.packet_history) % 100 == 0:  # Check every 100 packets
                alerts = self.anomaly_detector.check_anomalies()
                for alert in alerts:
                    self._handle_alert(alert)
    
    def _handle_alert(self, alert: Dict[str, Any]):
        """Handle generated alert"""
        self.total_alerts += 1
        self.alerts_by_type[alert['type']] += 1
        
        logger.warning(f"ALERT: {alert['type']} - {alert['message']}")
        
        if self.alert_callback: 
            self.alert_callback(alert)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        stats = {
            'total_alerts': self.total_alerts,
            'alerts_by_type': dict(self.alerts_by_type),
            'packets_analyzed': len(self.packet_history),
        }
        
        if self.anomaly_detector:
            stats['anomaly_stats'] = self.anomaly_detector.get_stats()
        
        return stats


class SignatureDetector:
    """Signature-based intrusion detection"""
    
    def __init__(self, alert_callback: Optional[callable] = None):
        self.alert_callback = alert_callback
        self.port_scan_detector = PortScanDetector()
        self.suspicious_patterns = config.SUSPICIOUS_PATTERNS
        self.suspicious_ports = config.SUSPICIOUS_PORTS
        
    def check_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check packet against known attack signatures"""
        alerts = []
        
        # Check for suspicious ports
        if packet_info.get('dst_port') in self.suspicious_ports:
            alerts.append({
                'type': 'SUSPICIOUS_PORT',
                'severity': 'MEDIUM',
                'message': f"Connection to suspicious port {packet_info['dst_port']} from {packet_info.get('src_ip')}",
                'src_ip': packet_info.get('src_ip'),
                'dst_ip': packet_info.get('dst_ip'),
                'dst_port': packet_info.get('dst_port'),
                'timestamp': time.time(),
            })
        
        # Check for suspicious patterns in payload
        payload = packet_info.get('payload')
        if payload:
            payload_lower = payload.lower()
            for pattern in self.suspicious_patterns:
                if pattern.lower() in payload_lower:
                    alerts.append({
                        'type': 'SUSPICIOUS_PAYLOAD',
                        'severity': 'HIGH',
                        'message': f"Suspicious pattern detected in payload from {packet_info.get('src_ip')}",
                        'pattern': pattern.decode('utf-8', errors='ignore'),
                        'src_ip': packet_info.get('src_ip'),
                        'dst_ip': packet_info.get('dst_ip'),
                        'timestamp': time.time(),
                    })
                    break
        
        # Check for port scanning
        scan_alert = self.port_scan_detector.check_packet(packet_info)
        if scan_alert:
            alerts.append(scan_alert)
        
        return alerts


class PortScanDetector:
    """Detect port scanning attempts"""
    
    def __init__(self, threshold: int = 10, time_window: int = 60):
        """
        Initialize port scan detector
        
        Args:
            threshold: Number of unique ports to trigger alert
            time_window: Time window in seconds
        """
        self.threshold = threshold
        self.time_window = time_window
        self.scan_attempts = defaultdict(lambda: {'ports': set(), 'first_seen': None, 'last_seen': None})
        
    def check_packet(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if packet indicates port scanning"""
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        
        if not src_ip or not dst_port:
            return None
        
        current_time = time.time()
        
        # Clean old entries
        if src_ip in self.scan_attempts:
            entry = self.scan_attempts[src_ip]
            if current_time - entry['last_seen'] > self.time_window:
                del self.scan_attempts[src_ip]
                return None
        
        # Update scan attempt tracking
        if src_ip not in self.scan_attempts:
            self.scan_attempts[src_ip]['first_seen'] = current_time
        
        self.scan_attempts[src_ip]['ports'].add(dst_port)
        self.scan_attempts[src_ip]['last_seen'] = current_time
        
        # Check if threshold exceeded
        if len(self.scan_attempts[src_ip]['ports']) >= self.threshold:
            entry = self.scan_attempts[src_ip]
            duration = entry['last_seen'] - entry['first_seen']
            
            # Generate alert and reset
            alert = {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'message': f"Port scan detected from {src_ip}: {len(entry['ports'])} unique ports in {duration:.1f}s",
                'src_ip': src_ip,
                'ports_scanned': len(entry['ports']),
                'duration': duration,
                'timestamp': current_time,
            }
            
            del self.scan_attempts[src_ip]
            return alert
        
        return None


class AnomalyDetector:
    """Anomaly-based intrusion detection using statistical analysis"""
    
    def __init__(self, alert_callback: Optional[callable] = None):
        self.alert_callback = alert_callback
        self.packet_sizes = deque(maxlen=10000)
        self.packet_rates = defaultdict(lambda: deque(maxlen=1000))
        self.connection_counts = defaultdict(int)
        self.stats = {
            'mean_packet_size': 0,
            'std_packet_size': 0,
            'baseline_established': False,
        }
        
    def update_stats(self, packet_info: Dict[str, Any]):
        """Update statistical baseline"""
        packet_size = packet_info.get('size', 0)
        self.packet_sizes.append(packet_size)
        
        src_ip = packet_info.get('src_ip')
        if src_ip:
            current_time = time.time()
            self.packet_rates[src_ip].append(current_time)
            self.connection_counts[src_ip] += 1
        
        # Update baseline statistics
        if len(self.packet_sizes) >= config.MIN_PACKETS_FOR_ANALYSIS:
            sizes = np.array(self.packet_sizes)
            self.stats['mean_packet_size'] = np.mean(sizes)
            self.stats['std_packet_size'] = np.std(sizes)
            self.stats['baseline_established'] = True
    
    def check_anomalies(self) -> List[Dict[str, Any]]:
        """Check for anomalies in network traffic"""
        alerts = []
        
        if not self.stats['baseline_established']:
            return alerts
        
        # Check for unusual packet sizes
        if len(self.packet_sizes) > 0:
            recent_sizes = list(self.packet_sizes)[-100:]
            for size in recent_sizes:
                if self.stats['std_packet_size'] > 0:
                    z_score = abs(size - self.stats['mean_packet_size']) / self.stats['std_packet_size']
                    if z_score > config.ANOMALY_THRESHOLD:
                        alerts.append({
                            'type': 'ANOMALOUS_PACKET_SIZE',
                            'severity': 'MEDIUM',
                            'message': f"Unusual packet size detected: {size} bytes (z-score: {z_score:.2f})",
                            'packet_size': size,
                            'z_score': z_score,
                            'timestamp': time.time(),
                        })
        
        # Check for unusual packet rates
        current_time = time.time()
        for src_ip, timestamps in list(self.packet_rates.items()):
            if len(timestamps) < 10:
                continue
            
            # Count packets in last minute
            recent_timestamps = [ts for ts in timestamps if current_time - ts < 60]
            packet_rate = len(recent_timestamps)
            
            # Calculate average rate (simple heuristic)
            if len(timestamps) > 100:
                avg_rate = len(timestamps) / 100
                if packet_rate > avg_rate * 3:  # 3x average rate
                    alerts.append({
                        'type': 'ANOMALOUS_TRAFFIC_RATE',
                        'severity': 'HIGH',
                        'message': f"Unusual traffic rate from {src_ip}: {packet_rate} packets/min",
                        'src_ip': src_ip,
                        'packet_rate': packet_rate,
                        'timestamp': current_time,
                    })
        
        # Check for connection flooding
        for src_ip, count in list(self.connection_counts.items()):
            if count > config.MAX_CONNECTIONS_PER_IP:
                alerts.append({
                    'type': 'CONNECTION_FLOOD',
                    'severity': 'HIGH',
                    'message': f"Connection flood detected from {src_ip}: {count} connections",
                    'src_ip': src_ip,
                    'connection_count': count,
                    'timestamp': current_time,
                })
                # Reset counter
                self.connection_counts[src_ip] = 0
        
        return alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get anomaly detection statistics"""
        return self.stats.copy()

