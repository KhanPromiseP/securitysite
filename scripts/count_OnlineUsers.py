import os
import subprocess
import time
import signal
import logging
from scapy.all import ARP, Ether, srp  # For sending ARP requests and analyzing responses
import netifaces  # Library to retrieve network interface details
import mysql.connector  # It is for database operations
from datetime import datetime  # Responsible for timestamping
import socket  # Socket helps us for resolving hostnames

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'securityapp'
}

# Initialize logger for logging to track events and errors for real-time monitoring
logging.basicConfig(
    filename='../logs/online_users.log', 
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Persistent tracking settings (Number of scans to wait before confirming a device has left)
DEVICE_TIMEOUT = 3

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as e:
        logging.error(f"Error connecting to the database: {e}")
        return None

def get_data_usage(ip):
    try:
        result = subprocess.check_output(["iptables", "-L", "FORWARD", "-vxn"], text=True)
        lines = result.splitlines()
        total_bytes = 0
        for line in lines:
            if ip in line:
                parts = line.split()
                if len(parts) > 1:
                    total_bytes += int(parts[1])
        return round(total_bytes / (1024 * 1024), 2)  # Convert to MB
    except Exception as e:
        logging.error(f"Failed to get data usage for {ip}: {e}")
        return 0.0


def auto_configure_firewall():
    try:
        # Enable IP forwarding
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        logging.info("IP forwarding enabled.")

        # Detect subnet from network interface
        try:
            default_gateway = netifaces.gateways()["default"][netifaces.AF_INET][1]
            iface_data = netifaces.ifaddresses(default_gateway)[netifaces.AF_INET][0]
            ip_address = iface_data["addr"]
            netmask = iface_data["netmask"]
            cidr = sum(bin(int(x)).count("1") for x in netmask.split("."))
            subnet = f"{ip_address}/{cidr}"
        except Exception as e:
            logging.error(f"Failed to detect subnet: {e}")
            subnet = "192.168.0.0/16"  # fallback

        # Add iptables rules to track traffic
        try:
            subprocess.run(["iptables", "-C", "FORWARD", "-s", subnet, "-j", "ACCEPT"], stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            subprocess.run(["iptables", "-I", "FORWARD", "-s", subnet, "-j", "ACCEPT"])
            subprocess.run(["iptables", "-I", "FORWARD", "-d", subnet, "-j", "ACCEPT"])
            logging.info(f"iptables rules added for subnet: {subnet}")
        
    except Exception as e:
        logging.error(f"Auto firewall configuration failed: {e}")


def ensure_iptables_rule(ip):
    try:
        # Check if rule exists for source IP
        subprocess.run(["iptables", "-C", "FORWARD", "-s", ip, "-j", "ACCEPT"], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "ACCEPT"])
        logging.info(f"iptables rule added for source IP: {ip}")

    try:
        # Check if rule exists for destination IP
        subprocess.run(["iptables", "-C", "FORWARD", "-d", ip, "-j", "ACCEPT"], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.run(["iptables", "-I", "FORWARD", "-d", ip, "-j", "ACCEPT"])
        logging.info(f"iptables rule added for destination IP: {ip}")




def save_to_db(ip, mac_address, hostname="Unknown"):
    db_connection = get_db_connection()
    if not db_connection:
        return

    try:
        ensure_iptables_rule(ip)
        cursor = db_connection.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data_usage_mb = get_data_usage(ip)
        query = """
            INSERT INTO active_users_log (ip_address, mac_address, hostname, timestamp, data_usage_mb)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE hostname = %s, timestamp = %s, data_usage_mb = %s
        """
        cursor.execute(query, (
            ip, mac_address, hostname, timestamp, data_usage_mb,
            hostname, timestamp, data_usage_mb
        ))
        db_connection.commit()
        logging.info(f"Device saved to DB: IP={ip}, MAC={mac_address}, Hostname={hostname}, Data={data_usage_mb} MB")
    except mysql.connector.Error as e:
        logging.error(f"Error saving device to database: {e}")
    finally:
        cursor.close()
        db_connection.close()


def delete_from_db(ip):
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

def delete_all_from_db():
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

def get_network_subnet():
    try:
        default_gateway = netifaces.gateways()["default"][netifaces.AF_INET][1]
        iface_data = netifaces.ifaddresses(default_gateway)[netifaces.AF_INET][0]
        ip_address = iface_data["addr"]
        netmask = iface_data["netmask"]
        cidr = sum(bin(int(x)).count("1") for x in netmask.split("."))
        return f"{ip_address}/{cidr}"
    except KeyError:
        raise RuntimeError("Unable to detect the subnet. Ensure the system is connected to a network.")

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"

def scan_network(network):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    responses, _ = srp(packet, timeout=2, verbose=False)
    devices = []
    for _, resp in responses:
        ip = resp.psrc
        mac = resp.hwsrc
        hostname = resolve_hostname(ip)
        devices.append((ip, mac, hostname))
    return devices

def signal_all_user():
    delete_all_from_db()
    logging.info("All users signaled (database cleared).")

def real_time_network_tracker():
    try:
        network = get_network_subnet()
        logging.info(f"Detected subnet: {network}")

        print("\nReal-time network tracker running...   Press Ctrl+C 'twice' to stop.\n")
        active_devices = {}
        unseen_counts = {}

        # while True:
        try:
            scanned_devices = scan_network(network)
            current_devices = {ip: (mac, hostname) for ip, mac, hostname in scanned_devices}

            for ip, (mac, hostname) in current_devices.items():
                if ip not in active_devices:
                    save_to_db(ip, mac, hostname)
                    # print(f"[+] New device detected: IP={ip}, MAC={mac}, Hostname={hostname}")
                    # logging.info(f"New device detected: IP={ip}, MAC={mac}, Hostname={hostname}")
                active_devices[ip] = (mac, hostname)
                unseen_counts[ip] = 0
            print(f"[+] New device detected: IP={ip}, MAC={mac}, Hostname={hostname}")
            logging.info(f"New device detected: IP={ip}, MAC={mac}, Hostname={hostname}")

            for ip in list(active_devices.keys()):
                if ip not in current_devices:
                    unseen_counts[ip] += 1
                    if unseen_counts[ip] >= DEVICE_TIMEOUT:
                        delete_from_db(ip)
                        logging.info(f"Device removed: IP={ip}")
                        del active_devices[ip]
                        del unseen_counts[ip]

            device_count = len(active_devices)
            logging.info(f"Current device count: {device_count}")
            time.sleep(1)

        except Exception as e:
            logging.error(f"Error during scanning: {e}")
            signal_all_user()
           

    except KeyboardInterrupt:
        print("\nStopping the network tracker.")
        logging.info("Network tracker stopped by the Security Admin.")
        signal_all_user()
    except Exception as e:
        logging.error(f"Error: {e}")
        signal_all_user()

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda signum, frame: signal_all_user())
    auto_configure_firewall()
    real_time_network_tracker()
