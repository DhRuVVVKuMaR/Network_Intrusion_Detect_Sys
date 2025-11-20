from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
from datetime import datetime
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global references to NIDS components
packet_capture = None
detection_engine = None
alert_system = None


def init_dashboard(nids_packet_capture, nids_detection_engine, nids_alert_system):
    """Initialize dashboard with NIDS components"""
    global packet_capture, detection_engine, alert_system
    packet_capture = nids_packet_capture
    detection_engine = nids_detection_engine
    alert_system = nids_alert_system


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    stats = {
        'capture': packet_capture.get_stats() if packet_capture else {},
        'detection': detection_engine.get_stats() if detection_engine else {},
        'alerts': alert_system.get_statistics() if alert_system else {},
        'timestamp': time.time(),
    }
    return jsonify(stats)


@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    limit = 100
    alerts = alert_system.get_recent_alerts(limit) if alert_system else []
    return jsonify(alerts)


@app.route('/api/connections')
def get_connections():
    """Get connection statistics"""
    connections = packet_capture.get_connection_stats() if packet_capture else {}
    return jsonify(connections)


@app.route('/api/inject_packet', methods=['POST'])
def inject_packet():
    """Inject a test packet into the detection engine (for testing without WinPcap)"""
    if not detection_engine:
        return jsonify({'error': 'Detection engine not initialized'}), 500
    
    try:
        data = request.get_json()
        
        # Create packet info from request
        packet_info = {
            'timestamp': time.time(),
            'size': data.get('size', 100),
            'protocol': data.get('protocol', 'TCP'),
            'src_ip': data.get('src_ip', '127.0.0.1'),
            'dst_ip': data.get('dst_ip', '127.0.0.1'),
            'src_port': data.get('src_port'),
            'dst_port': data.get('dst_port'),
            'payload': data.get('payload'),
            'raw': None,
        }
        
        # Also update packet capture stats if available
        if packet_capture:
            packet_capture.stats['total_packets'] += 1
            packet_capture.stats['bytes_captured'] += packet_info['size']
            
            if packet_info['protocol'] == 'TCP':
                packet_capture.stats['tcp_packets'] += 1
            elif packet_info['protocol'] == 'UDP':
                packet_capture.stats['udp_packets'] += 1
            elif packet_info['protocol'] == 'ICMP':
                packet_capture.stats['icmp_packets'] += 1
        
        # Analyze the packet
        detection_engine.analyze_packet(packet_info)
        
        return jsonify({'status': 'success', 'message': 'Packet injected and analyzed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('status', {'message': 'Connected to NIDS Dashboard'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')


def start_dashboard_update_thread():
    """Start background thread to push updates to clients"""
    def update_loop():
        while True:
            try:
                if packet_capture and detection_engine and alert_system:
                    stats = {
                        'capture': packet_capture.get_stats(),
                        'detection': detection_engine.get_stats(),
                        'alerts': alert_system.get_statistics(),
                        'timestamp': time.time(),
                    }
                    socketio.emit('stats_update', stats)
                    
                    # Send recent alerts
                    recent_alerts = alert_system.get_recent_alerts(10)
                    if recent_alerts:
                        socketio.emit('new_alerts', recent_alerts)
                
                time.sleep(2)  # Update every 2 seconds
            except Exception as e:
                print(f"Error in update loop: {e}")
                time.sleep(5)
    
    thread = threading.Thread(target=update_loop, daemon=True)
    thread.start()
    


def run_dashboard(host='0.0.0.0', port=5000, debug=False):
    """Run the dashboard server"""
    start_dashboard_update_thread()
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)

