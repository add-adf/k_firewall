import psutil
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_running_apps():
    """
    Returns a list of running applications and their PIDs.
    """
    apps = []
    for proc in psutil.process_iter(['pid', 'name']):
        apps.append({"name": proc.info['name'], "pid": proc.info['pid']})
    return apps