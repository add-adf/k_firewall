import requests
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_signatures():
    """
    Fetches signatures from the central server.
    """
    try:
        response = requests.get("http://central-server/signatures")  # Replace with your server URL
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch signatures: {e}")
        return {}

def match_signatures(packet, signatures):
    """
    Matches the packet against the signature database.
    """
    if packet.haslayer("IP"):
        # Check for malicious domains
        if packet.haslayer("DNS"):
            for domain in signatures.get("malicious_domains", []):
                if domain in str(packet["DNS"].qd):
                    return f"Malicious domain: {domain}"

        # Check for malicious IPs
        for ip in signatures.get("malicious_ips", []):
            if ip == packet["IP"].dst:
                return f"Malicious IP: {ip}"

        # Check for malicious patterns in payload
        if packet.haslayer("Raw"):
            for pattern in signatures.get("malicious_patterns", []):
                if pattern in str(packet["Raw"].load):
                    return f"Malicious pattern: {pattern}"
    return None