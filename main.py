"""
Main entry point for Network Intrusion Detection System
"""

import sys
import signal
import threading
import time
import logging
import config
from packet_capture import PacketCapture
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from dashboard import init_dashboard, run_dashboard

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NIDS:
    """Network Intrusion Detection System main class"""
    
    def __init__(self):
        self.alert_system = AlertSystem()
        self.detection_engine = DetectionEngine(alert_callback=self.alert_system.handle_alert)
        self.packet_capture = PacketCapture(
            interface=config.NETWORK_INTERFACE,
            packet_callback=self.detection_engine.analyze_packet
        )
        self.dashboard_thread = None
        self.running = False
        
    def start(self):
        """Start the NIDS"""
        if self.running:
            logger.warning("NIDS is already running")
            return
        
        logger.info("Starting Network Intrusion Detection System...")
        logger.info(f"Network Interface: {self.packet_capture.interface}")
        logger.info(f"Signature Detection: {'Enabled' if config.SIGNATURE_DETECTION_ENABLED else 'Disabled'}")
        logger.info(f"Anomaly Detection: {'Enabled' if config.ANOMALY_DETECTION_ENABLED else 'Disabled'}")
        
        # Start packet capture
        self.packet_capture.start_capture()
        
        # Initialize and start dashboard
        init_dashboard(self.packet_capture, self.detection_engine, self.alert_system)
        self.dashboard_thread = threading.Thread(
            target=run_dashboard,
            args=(config.WEB_HOST, config.WEB_PORT, config.WEB_DEBUG),
            daemon=True
        )
        self.dashboard_thread.start()
        
        self.running = True
        logger.info(f"Dashboard available at http://{config.WEB_HOST}:{config.WEB_PORT}")
        logger.info("NIDS is now running. Press Ctrl+C to stop.")
    
    def stop(self):
        """Stop the NIDS"""
        if not self.running:
            return
        
        logger.info("Stopping NIDS...")
        self.running = False
        self.packet_capture.stop_capture()
        logger.info("NIDS stopped")
    
    def print_stats(self):
        """Print current statistics"""
        if not self.running:
            return
        
        capture_stats = self.packet_capture.get_stats()
        detection_stats = self.detection_engine.get_stats()
        alert_stats = self.alert_system.get_statistics()
        
        print("\n" + "="*60)
        print("NIDS Statistics")
        print("="*60)
        print(f"Capture Runtime: {capture_stats.get('runtime', 0):.1f}s")
        print(f"Total Packets: {capture_stats.get('total_packets', 0):,}")
        print(f"Packets/sec: {capture_stats.get('packets_per_second', 0):.2f}")
        print(f"Bytes Captured: {capture_stats.get('bytes_captured', 0):,}")
        print(f"Active Connections: {capture_stats.get('active_connections', 0)}")
        print(f"\nTotal Alerts: {detection_stats.get('total_alerts', 0)}")
        print(f"Packets Analyzed: {detection_stats.get('packets_analyzed', 0):,}")
        print(f"\nAlert Breakdown:")
        for alert_type, count in alert_stats.get('by_type', {}).items():
            print(f"  {alert_type}: {count}")
        print("="*60 + "\n")


def signal_handler(sig, frame):
    """Handle shutdown signals"""
    print("\nShutting down...")
    if 'nids' in globals():
        nids.stop()
    sys.exit(0)


def main():
    """Main entry point"""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check for admin/root privileges
    import platform
    if platform.system() == 'Windows':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.warning("Warning: Not running as administrator. Packet capture may not work properly.")
        except:
            pass
    else:
        import os
        if os.geteuid() != 0:
            logger.warning("Warning: Not running as root. Packet capture may not work properly.")
            logger.warning("Try running with: sudo python main.py")
    
    # Create and start NIDS
    global nids
    nids = NIDS()
    
    try:
        nids.start()
        
        # Print stats periodically
        while nids.running:
            time.sleep(30)  # Print stats every 30 seconds
            nids.print_stats()
            
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        nids.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()








