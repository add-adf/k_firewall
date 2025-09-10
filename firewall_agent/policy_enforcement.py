from signature_detection import fetch_signatures, match_signatures
import requests
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def fetch_policies():
    """
    Fetches policies from the central server.
    """
    logger.debug("Fetching policies...")
    try:
        response = requests.get("http://central-server/policies")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch policies: {e}")
        return []

def enforce_policies(packet, log_callback):
    """
    Enforces firewall policies and signature-based detection on the given packet.
    """
    logger.debug("Enforcing policies...")
    # Fetch policies and signatures
    policies = fetch_policies()
    signatures = fetch_signatures()

    # Check for malicious signatures
    signature_match = match_signatures(packet, signatures)
    if signature_match:
        logger.warning(f"Blocked packet due to {signature_match}")
        return  # Drop the packet

    # Enforce policies
    for policy in policies:
        if policy["app_name"] in str(packet):  # Replace with actual app name detection
            if packet.haslayer("IP"):
                if packet["IP"].dst in policy["blocked_ips"]:
                    logger.warning(f"Blocked packet from {packet['IP'].src} to {packet['IP'].dst}")
                    return  # Drop the packet

    # If no policies or signatures are violated, log the packet
    log_callback(packet)