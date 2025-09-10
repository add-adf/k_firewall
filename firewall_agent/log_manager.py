import requests
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def log_activity(packet):
    """
    Logs network activity and sends logs to the central server.
    """
    logger.debug("Logging activity...")
    if packet.haslayer("IP"):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "app_name": "chrome.exe",  # Replace with actual app name detection
            "domain": packet["IP"].dst,
            "protocol": "TCP" if packet.haslayer("TCP") else "UDP"
        }

        # Log to console
        logger.info(f"Log Entry: {log_entry}")

        # Send log to central server
        try:
            response = requests.post(
                "http://central-server/logs",  # Replace with your server URL
                json=log_entry,
                headers={"Content-Type": "application/json"},
                timeout=5  # Timeout after 5 seconds
            )
            response.raise_for_status()
            logger.info(f"Log sent to server. Response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send log: {e}")