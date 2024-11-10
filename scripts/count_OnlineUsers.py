import platform
import subprocess
import re
import logging
import socket
import time
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    filename="../logs/online_users.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_local_subnet():
    """Determine the subnet of the local network based on the host's IP."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    # Assume a /24 subnet for simplicity, typically used in home networks
    subnet = f"{local_ip}/24"
    logging.info(f"Determined local subnet: {subnet}")
    return subnet

def ping_sweep(subnet):
    """Ping each address in the subnet to populate the ARP cache."""
    network = ip_network(subnet, strict=False)
    logging.info(f"Starting ping sweep on subnet {subnet}")
    for ip in network.hosts():
        subprocess.Popen(['ping', '-c', '1', '-W', '500', str(ip)],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

def is_alive(ip):
    """Check if a given IP is reachable via socket or ICMP ping."""
    try:
        socket.setdefaulttimeout(0.5)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 80))
        return True
    except socket.error:
        response = subprocess.run(['ping', '-c', '1', '-W', '500', ip], stdout=subprocess.DEVNULL)
        return response.returncode == 0

def fetch_active_ips_nmap(subnet):
    """Use nmap to get active IP addresses in the subnet."""
    active_ips = set()
    try:
        logging.info(f"Running nmap scan on subnet {subnet}")
        result = subprocess.run(['nmap', '-sn', subnet], stdout=subprocess.PIPE, text=True)
        active_ips = set(re.findall(r'(\d+\.\d+\.\d+\.\d+)', result.stdout))
        logging.debug(f"nmap output: {result.stdout}")
    except Exception as e:
        logging.error(f"Error running nmap: {e}")
    return active_ips

def fetch_arp_cache():
    """Fetch IP addresses from the ARP cache depending on the OS."""
    os_type = platform.system()
    active_ips = set()
    try:
        if os_type == "Linux":
            logging.info("Fetching ARP cache on Linux")
            result = subprocess.run(['ip', 'neighbor'], stdout=subprocess.PIPE, text=True)
            active_ips = set(re.findall(r'(\d+\.\d+\.\d+\.\d+)', result.stdout))
            logging.debug(f"ip neighbor output: {result.stdout}")
        elif os_type == "Windows":
            logging.info("Fetching ARP cache on Windows")
            result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE, text=True)
            active_ips = set(re.findall(r'(\d+\.\d+\.\d+\.\d+)', result.stdout))
            logging.debug(f"ARP cache output: {result.stdout}")
        else:
            logging.warning("Unsupported OS detected. Exiting without scanning.")
    except Exception as e:
        logging.error(f"Error retrieving ARP cache: {e}")
    return active_ips

def count_active_devices(subnet):
    """Count and verify active devices on the network."""
    # Perform a ping sweep to populate the ARP cache
    ping_sweep(subnet=subnet)

    # Fetch active IPs using ARP or nmap
    active_ips = fetch_arp_cache()
    if not active_ips:
        # Fall back to nmap if ARP cache is empty
        active_ips = fetch_active_ips_nmap(subnet=subnet)

    verified_ips = set()
    # Multithreading for faster verification
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(is_alive, ip): ip for ip in active_ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                verified_ips.add(ip)
                logging.debug(f"Verified active IP: {ip}")

    return verified_ips

def monitor_devices():
    """Continuously monitor for device changes and update in real-time."""
    subnet = get_local_subnet()
    known_devices = set()

    while True:
        active_devices = count_active_devices(subnet=subnet)

        # Check for new devices
        new_devices = active_devices - known_devices
        if new_devices:
            print(f"New devices detected: {new_devices}")
            logging.info(f"New devices: {new_devices}")

        # Check for removed devices
        removed_devices = known_devices - active_devices
        if removed_devices:
            print(f"Devices disconnected: {removed_devices}")
            logging.info(f"Disconnected devices: {removed_devices}")

        # Update known devices
        known_devices = active_devices
        print(f"Total connected devices: {len(known_devices)}")

        # Sleep for a short duration before the next scan
        time.sleep(5)

if __name__ == "__main__":
    logging.info("Starting real-time network device monitor")
    try:
        monitor_devices()
    except KeyboardInterrupt:
        logging.info("Network monitor script terminated by user.")
