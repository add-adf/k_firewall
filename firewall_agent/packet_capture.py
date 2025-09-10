from scapy.all import sniff
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def start_packet_capture(packet_callback):
    """
    Starts capturing network packets and calls the provided callback for each packet.
    """
    logger.debug("Starting packet capture...")
    sniff(prn=packet_callback, store=False)