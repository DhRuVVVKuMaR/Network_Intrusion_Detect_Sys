"""
Alert and logging system for intrusion detection alerts
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Any
from collections import deque
import json
import os
import config

logger = logging.getLogger(__name__)


class AlertSystem:
    """Handle alerts and notifications"""
    
    def __init__(self):
        self.alerts = deque(maxlen=1000)  # Store last 1000 alerts
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # File handler
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            config.LOG_FILE,
            maxBytes=config.MAX_LOG_SIZE_MB * 1024 * 1024,
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(log_format))
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, config.LOG_LEVEL))
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
    
    def handle_alert(self, alert: Dict[str, Any]):
        """
        Handle an intrusion detection alert
        
        Args:
            alert: Alert dictionary with type, severity, message, etc.
        """
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        else:
            alert['timestamp'] = datetime.fromtimestamp(alert['timestamp']).isoformat()
        
        # Store alert
        self.alerts.append(alert)
        
        # Log alert
        severity = alert.get('severity', 'UNKNOWN')
        alert_type = alert.get('type', 'UNKNOWN')
        message = alert.get('message', 'No message')
        
        log_message = f"[{severity}] {alert_type}: {message}"
        
        if severity == 'HIGH':
            logger.critical(log_message)
        elif severity == 'MEDIUM':
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        # Send email alert if configured
        if config.ALERT_EMAIL_ENABLED and severity in ['HIGH', 'CRITICAL']:
            self._send_email_alert(alert)
        
        # Print to console with color
        self._print_alert(alert)
    
    def _print_alert(self, alert: Dict[str, Any]):
        """Print alert to console with color coding"""
        try:
            from colorama import init, Fore, Style
            init(autoreset=True)
            
            severity = alert.get('severity', 'UNKNOWN')
            alert_type = alert.get('type', 'UNKNOWN')
            message = alert.get('message', 'No message')
            timestamp = alert.get('timestamp', '')
            
            # Color coding by severity
            if severity == 'HIGH':
                color = Fore.RED + Style.BRIGHT
            elif severity == 'MEDIUM':
                color = Fore.YELLOW
            else:
                color = Fore.CYAN
            
            print(f"{color}[{severity}] {alert_type}: {message} {Style.RESET_ALL}({timestamp})")
        except ImportError:
            # Fallback if colorama not available
            print(f"[{alert['severity']}] {alert['type']}: {alert['message']} ({alert.get('timestamp', '')})")
    
    def _send_email_alert(self, alert: Dict[str, Any]):
        """Send email alert"""
        if not config.ALERT_EMAIL_FROM or not config.ALERT_EMAIL_TO:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = config.ALERT_EMAIL_FROM
            msg['To'] = config.ALERT_EMAIL_TO
            msg['Subject'] = f"NIDS Alert: {alert.get('type', 'Unknown')}"
            
            body = f"""
Network Intrusion Detection System Alert

Severity: {alert.get('severity', 'UNKNOWN')}
Type: {alert.get('type', 'UNKNOWN')}
Message: {alert.get('message', 'No message')}
Timestamp: {alert.get('timestamp', 'Unknown')}

Additional Details:
{json.dumps(alert, indent=2)}
"""
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(config.ALERT_EMAIL_SMTP_SERVER, config.ALERT_EMAIL_SMTP_PORT)
            server.starttls()
            # Note: In production, use environment variables or secure storage for credentials
            # server.login(email, password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent for {alert.get('type')}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return list(self.alerts)[-limit:]
    
    def get_alerts_by_type(self, alert_type: str) -> List[Dict[str, Any]]:
        """Get alerts filtered by type"""
        return [alert for alert in self.alerts if alert.get('type') == alert_type]
    
    def get_alerts_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get alerts filtered by severity"""
        return [alert for alert in self.alerts if alert.get('severity') == severity]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        total = len(self.alerts)
        by_type = {}
        by_severity = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        
        for alert in self.alerts:
            alert_type = alert.get('type', 'UNKNOWN')
            by_type[alert_type] = by_type.get(alert_type, 0) + 1
            
            severity = alert.get('severity', 'UNKNOWN')
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total_alerts': total,
            'by_type': by_type,
            'by_severity': by_severity,
        }








