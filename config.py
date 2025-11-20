"""
Configuration settings for the Network Intrusion Detection System
"""

# Network Interface Configuration
NETWORK_INTERFACE = None  # None = auto-detect, or specify interface name like "eth0" or "Ethernet"

# Detection Settings
ANOMALY_DETECTION_ENABLED = True
SIGNATURE_DETECTION_ENABLED = True

# Anomaly Detection Thresholds
ANOMALY_THRESHOLD = 2.5  # Standard deviations from mean
MIN_PACKETS_FOR_ANALYSIS = 100

# Alert Settings
ALERT_EMAIL_ENABLED = False
ALERT_EMAIL_SMTP_SERVER = "smtp.gmail.com"
ALERT_EMAIL_SMTP_PORT = 587
ALERT_EMAIL_FROM = ""
ALERT_EMAIL_TO = ""

# Logging Settings
LOG_FILE = "nids.log"
LOG_LEVEL = "INFO"
MAX_LOG_SIZE_MB = 100

# Web Dashboard Settings
WEB_HOST = "0.0.0.0"
WEB_PORT = 5000
WEB_DEBUG = False

# Signature Detection Rules
SUSPICIOUS_PORTS = [
    23,   # Telnet
    135,  # MS RPC
    139,  # NetBIOS
    445,  # SMB
    1433, # SQL Server
    3389, # RDP
    4444, # Metasploit
    5555, # Android Debug Bridge
    6666, # IRC
    6667, # IRC
    31337, # Back Orifice
]

SUSPICIOUS_PATTERNS = [
    b"GET /etc/passwd",
    b"GET /proc/self/environ",
    b"union select",
    b"<script>",
    b"eval(",
    b"base64_decode",
    b"cmd.exe",
    b"/bin/sh",
]

# Rate Limiting
MAX_PACKETS_PER_SECOND = 10000
MAX_CONNECTIONS_PER_IP = 100

