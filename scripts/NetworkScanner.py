import scapy.all as scapy
from sklearn.ensemble import IsolationForest
import mysql.connector
import datetime
import logging
import numpy as np
import sys
import platform
import subprocess
import argparse
import socket
import struct
import psutil  # Added psutil for interface detection

# Setting up logging
logging.basicConfig(filename='../logs/network_monitor.log', filemode='a', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'security_app'
}

def connect_to_db():
    logging.debug("Attempting to connect to the database with config: %s", DB_CONFIG)
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        logging.debug("Database connection successful.")
        return conn
    except mysql.connector.Error as err:
        logging.error("Database connection error: %s", err)
        return None

def get_network_details():
    # Use psutil to find the active network interface and retrieve IP and netmask
    interfaces = psutil.net_if_addrs()
    subnet = None
    
    for iface_name, iface_addresses in interfaces.items():
        for address in iface_addresses:
            # Look for an IPv4 address that is not the loopback
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                local_ip = address.address
                netmask = address.netmask
                logging.info("Detected active interface %s with IP: %s and netmask: %s", iface_name, local_ip, netmask)

                try:
                    # Convert IP and netmask to binary, calculate network address
                    ip_struct = struct.unpack('!I', socket.inet_aton(local_ip))[0]
                    mask_struct = struct.unpack('!I', socket.inet_aton(netmask))[0]
                    network = socket.inet_ntoa(struct.pack('!I', ip_struct & mask_struct))
                    cidr = bin(mask_struct).count("1")
                    subnet = f"{network}/{cidr}"
                    logging.info("Calculated subnet: %s", subnet)
                    return subnet
                except OSError as e:
                    logging.error("Failed to calculate subnet for interface %s: %s", iface_name, e)

    if subnet is None:
        logging.error("No valid network interface found. Unable to determine subnet.")
        return None

def scan_subnet(count=100):
    subnet = get_network_details()
    if subnet is None:
        logging.error("Could not retrieve subnet details.")
        return

    logging.info("Starting subnet scan on %s with %d hosts", subnet, count)
    packets = scapy.sniff(count=count, filter="ip or tcp or udp or icmp", timeout=15)
    logging.debug("Captured %d packets.", len(packets))
    if not packets:
        logging.warning("No packets captured during scan.")
        return
    
    anomalies = detect_anomalies(packets)
    for pkt in anomalies:
        ip = pkt[scapy.IP].src
        threat_type, user_crime = classify_threat(pkt)
        logging.debug("Classified threat for IP %s as %s: %s", ip, threat_type, user_crime)
        insert_threat_and_block(ip, threat_type, user_crime)

def detect_anomalies(packets):
    logging.info("Starting anomaly detection.")
    data = np.array([[pkt.time, len(pkt), pkt[scapy.IP].ttl] for pkt in packets if hasattr(pkt, 'time') and pkt.haslayer(scapy.IP)])
    if len(data) < 2:
        logging.warning("Insufficient data (%d samples) for anomaly detection.", len(data))
        return []

    model = IsolationForest(contamination=0.01, n_estimators=100, max_samples='auto')
    predictions = model.fit_predict(data)
    anomalies = [pkt for i, pkt in enumerate(packets) if predictions[i] == -1]
    logging.info("Anomaly detection completed. Detected %d anomalies out of %d packets.", len(anomalies), len(packets))
    return anomalies

def classify_threat(pkt):
    flags = pkt.sprintf("%TCP.flags%")
    if len(pkt) > 1000:
        return "High Bandwidth Attack", "Suspicious Data Transfer"
    elif "S" in flags and "A" not in flags:
        return "Syn Flood Attack", "Possible Denial-of-Service"
    elif pkt.haslayer(scapy.ICMP) and pkt[scapy.ICMP].type == 8:
        return "ICMP Ping Sweep", "Reconnaissance"
    elif pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qdcount > 2:
        return "DNS Amplification", "Potential DDoS via DNS"
    elif pkt.haslayer(scapy.TCP) and flags == "FPU":
        return "FIN Scan", "Potential Stealth Scan"
    elif pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].len == 0:
        return "UDP Flood", "Possible Denial-of-Service"
    else:
        return "Unusual Activity", "Anomalous Packet Behavior"

def insert_threat_and_block(ip, threat_type, crime):
    logging.info("Inserting threat data for IP %s with threat type: %s and crime: %s", ip, threat_type, crime)
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO network_logs (ip_address, threat_type, user_crime, is_blocked, detected_at) VALUES (%s, %s, %s, %s, %s)",
                (ip, threat_type, crime, 1, datetime.datetime.now())
            )
            conn.commit()
            logging.info("Threat inserted and blocked for IP %s", ip)
            block_ip(ip)
        except mysql.connector.Error as err:
            logging.error("Failed to insert threat for IP %s: %s", ip, err)
        finally:
            cursor.close()
            conn.close()

def block_ip(ip):
    os_type = platform.system()
    try:
        if os_type == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        elif os_type == "Windows":
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", "remoteip=" + ip], check=True)
        else:
            logging.warning("Unsupported OS for automatic blocking: %s", os_type)
    except subprocess.CalledProcessError as e:
        logging.error("Error blocking IP %s: %s", ip, e)

def main():
    logging.info("Starting network monitoring script.")
    parser = argparse.ArgumentParser(description="Network Scanner Script")
    parser.add_argument("action", type=str, help="Action to perform (e.g., 'scan')")
    parser.add_argument("--count", type=int, default=100, help="The number of hosts to scan")

    args = parser.parse_args()
    if args.action.lower() == 'scan':
        scan_subnet(count=args.count)
    else:
        logging.error("Invalid action specified: %s", args.action)
        sys.exit(1)

if __name__ == "__main__":
    main()
