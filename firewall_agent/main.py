import logging
from packet_capture import start_packet_capture
from policy_enforcement import enforce_policies
from log_manager import log_activity
from app_monitor import get_running_apps

# Set up logging
logging.basicConfig(level=logging.DEBUG)  # Set to DEBUG for detailed logs
logger = logging.getLogger(__name__)

def main():
    logger.debug("Starting Firewall Agent...")
    
    # Example: Get running applications
    logger.debug("Running Applications:")
    for app in get_running_apps():
        logger.debug(f"Process: {app['name']} (PID: {app['pid']})")
    
    # Start packet capture with policy enforcement and logging
    logger.debug("Starting packet capture...")
    start_packet_capture(
        packet_callback=lambda packet: enforce_policies(packet, log_activity)
    )

if __name__ == "__main__":
    main()