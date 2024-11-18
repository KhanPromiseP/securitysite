import platform
import subprocess
import re
import logging
import socket
import time
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import json
import uuid

logging.basicConfig(
    filename="../logs/online_users.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

active_device_count = 0
lock = threading.Lock()  
active_devices = {}

def get_local_subnet():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    subnet = f"{local_ip}/24"
    logging.info(f"Determined local subnet: {subnet}")
    return subnet

def ping_sweep(subnet):
    network = ip_network(subnet, strict=False)
    for ip in network.hosts():
        subprocess.Popen(['ping', '-c', '1', '-W', '500', str(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def is_alive(ip):
    try:
        socket.setdefaulttimeout(0.5)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 80))
        return True
    except socket.error:
        response = subprocess.run(['ping', '-c', '1', '-W', '500', ip], stdout=subprocess.DEVNULL)
        return response.returncode == 0

def fetch_active_ips():
    os_type = platform.system()
    active_ips = set()
    try:
        if os_type == "Linux":
            result = subprocess.run(['ip', 'neighbor'], stdout=subprocess.PIPE, text=True)
        elif os_type == "Windows":
            result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE, text=True)
        else:
            return active_ips

        active_ips = set(re.findall(r'(\d+\.\d+\.\d+\.\d+)', result.stdout))
    except Exception as e:
        logging.error(f"Error retrieving ARP cache: {e}")
    return active_ips

def get_mac_address(ip):
    try:
        result = subprocess.run(['arp', '-n', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        match = re.search(r"(\w{2}[-:]\w{2}[-:]\w{2}[-:]\w{2}[-:]\w{2}[-:]\w{2})", result.stdout)
        if match:
            return match.group(0)
        return None
    except Exception as e:
        logging.error(f"Error retrieving MAC address for {ip}: {e}")
        return None

def update_active_devices():
    global active_device_count
    while True:
        subnet = get_local_subnet()
        ping_sweep(subnet=subnet)
        active_ips = fetch_active_ips()
        verified_ips = set()

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {executor.submit(is_alive, ip): ip for ip in active_ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                if future.result():
                    mac_address = get_mac_address(ip)
                    if mac_address:
                        verified_ips.add(ip)
                        active_devices[ip] = {'mac': mac_address, 'hostname': socket.gethostbyaddr(ip)[0] if ip else 'Unknown'}
        
        with lock:
            active_device_count = len(verified_ips)

        with open('active_device_count.json', 'w') as f:
            json.dump({'active_devices': active_device_count, 'devices': active_devices}, f)
   
        logging.info(f"Active devices: {active_device_count}")
        
        time.sleep(30)  

def real_time_updates():

    while True:
        time.sleep(1)
        if active_device_count > 0:
            logging.info(f"Active devices: {active_device_count}")
            print(f"Active devices: {active_device_count}")
        else:
            logging.info("No active devices detected.")
            print("No active devices detected.")

if __name__ == "__main__":

    threading.Thread(target=update_active_devices, daemon=True).start()

    threading.Thread(target=real_time_updates, daemon=True).start()

    while True:
        time.sleep(1)
