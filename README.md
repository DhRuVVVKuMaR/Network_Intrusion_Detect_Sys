# Network Intrusion Detection System (NIDS)

A comprehensive Network Intrusion Detection System built with Python that provides real-time network monitoring, threat detection, and alerting capabilities.

## Features

- **Real-time Packet Capture**: Monitor network traffic in real-time
- **Signature-based Detection**: Detect known attack patterns and signatures
- **Anomaly Detection**: Identify unusual network behavior using statistical analysis
- **Alert System**: Real-time alerts for detected threats
- **Web Dashboard**: Interactive web interface for monitoring and visualization
- **Logging**: Comprehensive logging of all network events and alerts

## Installation

1. Install Python 3.8 or higher
2. Install dependencies:
```bash
pip install -r requirements.txt
```

**Note**: On Windows, you may need to install Npcap or WinPcap for packet capture functionality.

## Usage

1. Start the system:
```bash
python main.py
```

2. Access the web dashboard at `http://localhost:5000`

3. The system will automatically start monitoring network traffic and alert on suspicious activities.

## Configuration

Edit `config.py` to customize detection rules, thresholds, and monitoring parameters.

## Requirements

- Python 3.8+
- Administrator/root privileges (for packet capture)
- Network interface access

## License

MIT








