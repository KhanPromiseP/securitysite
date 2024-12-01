import os
import subprocess
import time
import signal
import logging
from scapy.all import ARP, Ether, srp  # For sending ARP requests and analyzing responses
import netifaces  #library to retrieve network interface details
import mysql.connector  # It is for database operations
from datetime import datetime  # Responsible for timestamping
import socket  # socket helps us for resolving hostnames

db_config = { 
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'security_app'
}

# Initialize logger for logging to track events and errors for real time monitoring
logging.basicConfig(  
    filename='../logs/online_users.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(message)s'
)

# Persistent tracking settings (Number of scans to wait before confirming a device has left). This is to avoid error in counting active devices
DEVICE_TIMEOUT = 3  

def get_db_connection():  
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as e: 
        logging.error(f"Error connecting to the database: {e}")
        return None

def save_to_db(ip, mac_address, hostname="Unknown"): 
    db_connection = get_db_connection()
    if not db_connection:
        return

    try:
        cursor = db_connection.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        query = """
            INSERT INTO active_users_log (ip_address, mac_address, hostname, timestamp)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE hostname = %s, timestamp = %s
        """ 
        cursor.execute(query, (ip, mac_address, hostname, timestamp, hostname, timestamp))
        db_connection.commit()
        logging.info(f"Device saved to database: IP={ip}, MAC={mac_address}, Hostname={hostname}")
    except mysql.connector.Error as e: 
        logging.error(f"Error saving device to database: {e}")
    finally:  
        cursor.close()
        db_connection.close()

def delete_from_db(ip):  # Remove a specific device entry from the database
    db_connection = get_db_connection()
    if not db_connection:
        return

    try:
        cursor = db_connection.cursor()
        query = "DELETE FROM active_users_log WHERE ip_address = %s"
        cursor.execute(query, (ip,))
        db_connection.commit()
        logging.info(f"Device removed from database: IP={ip}")
    except mysql.connector.Error as e: 
        logging.error(f"Error removing device from database: {e}")
    finally:  
        cursor.close()
        db_connection.close()

def delete_all_from_db():  # Clear (delete) all device entries in case of network failure
    db_connection = get_db_connection()
    if not db_connection:
        return

    try:
        cursor = db_connection.cursor()
        query = "DELETE FROM active_users_log"
        cursor.execute(query)
        db_connection.commit()
        logging.info("All devices removed from database due to network loss.")
    except mysql.connector.Error as e:  
        logging.error(f"Error clearing the database: {e}")
    finally: 
        cursor.close()
        db_connection.close()

def get_network_subnet():  # Function that will automatically identify the local subnet for scanning
    try:
        default_gateway = netifaces.gateways()["default"][netifaces.AF_INET][1]
        iface_data = netifaces.ifaddresses(default_gateway)[netifaces.AF_INET][0]
        ip_address = iface_data["addr"]
        netmask = iface_data["netmask"]
        cidr = sum(bin(int(x)).count("1") for x in netmask.split("."))
        return f"{ip_address}/{cidr}"
    except KeyError:  
        raise RuntimeError("Unable to detect the subnet. Ensure the system is connected to a network.")

def resolve_hostname(ip):  # Resolving found IP address to a hostname
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):  
        return "Unknown"

def scan_network(network):  # The main function that perform network scan to detect active devices ARP request
    arp_request = ARP(pdst=network) 
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcasting ARP request
    packet = broadcast / arp_request
    responses, _ = srp(packet, timeout=2, verbose=False)  # Send and receive responses
    devices = []
    for _, resp in responses:
        ip = resp.psrc  # Extract IP address
        mac = resp.hwsrc  # Extract MAC address
        hostname = resolve_hostname(ip)  # Resolve the hostname
        devices.append((ip, mac, hostname))
    return devices

def real_time_network_tracker():  # Continuously track devices on the network
    try:
        network = get_network_subnet()  # Get the network subnet
        logging.info(f"Detected subnet: {network}")

        print("\nStarting real-time network tracker. Press Ctrl+C to stop.\n")
        active_devices = {} 
        unseen_counts = {} 

# Scanning the network, add new devices
        while True:
            try:
                scanned_devices = scan_network(network)  
                current_devices = {ip: (mac, hostname) for ip, mac, hostname in scanned_devices}

                for ip, (mac, hostname) in current_devices.items():
                    if ip not in active_devices: 
                        save_to_db(ip, mac, hostname)
                        # print(f"[+] New device detected: IP={ip}, MAC={mac}, Hostname={hostname}")
                        logging.info(f"New device detected: IP={ip}, MAC={mac}, Hostname={hostname}")
                    active_devices[ip] = (mac, hostname)
                    unseen_counts[ip] = 0  

                # Handling the process of removing devices
                for ip in list(active_devices.keys()):
                    if ip not in current_devices:
                        unseen_counts[ip] += 1  
                        if unseen_counts[ip] >= DEVICE_TIMEOUT:  # Remove a device after when the device is not found on thenetwork after 3(in this case) consegative scans
                            delete_from_db(ip)
                            # print(f"[-] Device removed: IP={ip}")
                            logging.info(f"Device removed: IP={ip}")
                            del active_devices[ip]
                            del unseen_counts[ip]

                device_count = len(active_devices)  
                logging.info(f"Current device count: {device_count}")
                # print(f"\rActive devices: {device_count}", end="")

                time.sleep(1)  # Wait before 1 sec for the next scan

            except Exception as e: 
                logging.error(f"Error during scanning: {e}")
                delete_all_from_db()
                break

    except KeyboardInterrupt:  # Handle manual termination of the system
        print("\nStopping the network tracker.")
        logging.info("Network tracker stopped by the Security Admin.")
        delete_all_from_db()
    except Exception as e:  
        logging.error(f"Error: {e}")
        delete_all_from_db()

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda signum, frame: delete_all_from_db())  # Handle termination signals 
    real_time_network_tracker()  # Start tracking ip addresses in the network
