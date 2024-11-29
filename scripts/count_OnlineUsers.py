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
import mysql.connector

# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'security_app'
}

# Setup logging
logging.basicConfig(
    filename="../logs/online_users.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

active_device_count = 0
lock = threading.Lock()  
active_devices = {}

# Establish MySQL connection
def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as e:
        logging.error(f"Error connecting to MySQL: {e}")
        return None

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

def is_alive(ip):
    try:
        socket.setdefaulttimeout(0.5)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 80))
        return True
    except socket.error:
        response = subprocess.run(['ping', '-c', '1', '-W', '500', ip], stdout=subprocess.DEVNULL)
        return response.returncode == 0

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

def save_to_db(ip, mac_address, hostname):
    try:
        db_connection = get_db_connection()
        if db_connection:
            cursor = db_connection.cursor()
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            query = """
                INSERT INTO active_users_log (ip_address, mac_address, hostname, timestamp)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE timestamp = %s
            """
            cursor.execute(query, (ip, mac_address, hostname, timestamp, timestamp))
            db_connection.commit()
            cursor.close()
            db_connection.close()
            logging.info(f"Stored/Updated active device: {ip} - {mac_address} - {hostname}")
    except mysql.connector.Error as e:
        logging.error(f"Error inserting/updating data into MySQL: {e}")

def delete_from_db(ip):
    try:
        db_connection = get_db_connection()
        if db_connection:
            cursor = db_connection.cursor()
            query = "DELETE FROM active_users_log WHERE ip_address = %s"
            cursor.execute(query, (ip,))
            db_connection.commit()
            cursor.close()
            db_connection.close()
            logging.info(f"Removed inactive device: {ip}")
    except mysql.connector.Error as e:
        logging.error(f"Error deleting device from MySQL: {e}")

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
                if future.result():  # IP is alive
                    mac_address = get_mac_address(ip)
                    if mac_address:
                        verified_ips.add(ip)
                        hostname = socket.gethostbyaddr(ip)[0] if ip else 'Unknown'
                        active_devices[ip] = {'mac': mac_address, 'hostname': hostname}
                        save_to_db(ip, mac_address, hostname)  
                else:
                    if ip in active_devices:
                        delete_from_db(ip)  
                        del active_devices[ip]

        db_connection = get_db_connection()
        if db_connection:
            try:
                cursor = db_connection.cursor()
                query = "SELECT ip_address FROM active_users_log"
                cursor.execute(query)
                db_ips = {row[0] for row in cursor.fetchall()}  
                stale_ips = db_ips - verified_ips  

                for stale_ip in stale_ips:
                    delete_from_db(stale_ip)

                cursor.close()
            except mysql.connector.Error as e:
                logging.error(f"Error fetching/removing stale IPs: {e}")
            finally:
                db_connection.close()

        with lock:
            active_device_count = len(verified_ips)

        with open('active_device_count.json', 'w') as f:
            json.dump({'active_devices': active_device_count, 'devices': active_devices}, f)
        
        logging.info(f"Active devices: {active_device_count}")
        
        time.sleep(5)


def real_time_updates():
    while True:
        time.sleep(5)
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
        time.sleep(5)
