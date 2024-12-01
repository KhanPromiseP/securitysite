import scapy.all as scapy
from sklearn.ensemble import IsolationForest
import mysql.connector
import datetime
import logging
import logging.handlers
import numpy as np
import sys
import platform
import subprocess
import argparse
import socket
import struct
import psutil
import os
import threading
import queue
import time

from count_OnlineUsers import real_time_network_tracker

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'security_app'
}

log_queue = queue.Queue()
queue_handler = logging.handlers.QueueHandler(log_queue)
logger = logging.getLogger()
logger.addHandler(queue_handler)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('../logs/networkmonitor.log', 'a')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)



PID_FILE = 'network_scan_pid.txt'

def check_pid_file():
    if not os.path.exists(PID_FILE):
        print("PID file not found. Exiting script.")
        sys.exit(0)


def log_listener():
    while True:
        try:
            record = log_queue.get()
            if record is None:
                break
            file_handler.handle(record)
        except Exception as e:
            print(f"Logging error: {e}", file=sys.stderr)

listener_thread = threading.Thread(target=log_listener, daemon=True)
listener_thread.start()

def connect_to_db():
    try:
        logging.info("Attempting to connect to the database...")
        conn = mysql.connector.connect(**DB_CONFIG)
        logging.info("Database connection successful.")
        return conn
    except mysql.connector.Error as err:
        logging.error("Database connection error: %s", err)
        return None

def check_if_ip_blocked(ip):
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT is_blocked FROM network_logs WHERE ip_address = %s", (ip,))
            result = cursor.fetchone()
            if result and result[0] == 1:
                logging.info("IP %s is already blocked and not functional.", ip)
                return True
            return False
        finally:
            cursor.close()
            conn.close()
    return False

def get_network_details():
    logging.info("Getting local network interface details...")
    interfaces = psutil.net_if_addrs()
    for iface_name, iface_addresses in interfaces.items():
        for address in iface_addresses:
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                local_ip = address.address
                netmask = address.netmask
                try:
                    ip_struct = struct.unpack('!I', socket.inet_aton(local_ip))[0]
                    mask_struct = struct.unpack('!I', socket.inet_aton(netmask))[0]
                    network = socket.inet_ntoa(struct.pack('!I', ip_struct & mask_struct))
                    cidr = bin(mask_struct).count("1")
                    subnet = f"{network}/{cidr}"
                    logging.info("Local subnet detected: %s", subnet)
                    return subnet
                except OSError as e:
                    logging.error("Failed to calculate subnet for interface %s: %s", iface_name, e)
    logging.error("No valid network interface found. Unable to determine subnet.")
    return None

def scan_subnet(count=100):
    logging.info("Scanning local subnet for suspicious activity...")
    subnet = get_network_details()
    if subnet is None:
        logging.error("Could not retrieve subnet details.")
        return

    packets = scapy.sniff(count=count, filter="ip or tcp or udp or icmp", timeout=15)
    logging.info("Packets captured: %d", len(packets))
    anomalies = detect_anomalies(packets)
    logging.info("Anomalies detected: %d", len(anomalies))

    for pkt in anomalies:
        ip = pkt[scapy.IP].src
        if not check_if_ip_blocked(ip):
            threat_type, user_crime, description = classify_threat(pkt)
            logging.info("Threat detected: %s from IP %s", threat_type, ip)
            insert_threat_and_block(ip, threat_type, user_crime, description)
        else:
            logging.info("Skipping IP %s as it is already blocked.", ip)

def detect_anomalies(packets):
    logging.info("Detecting anomalies in captured packets...")
    data = np.array([[pkt.time, len(pkt), pkt[scapy.IP].ttl] for pkt in packets if hasattr(pkt, 'time') and pkt.haslayer(scapy.IP)])
    if len(data) < 2:
        logging.info("Not enough data to detect anomalies.")
        return []

    model = IsolationForest(contamination=0.01, n_estimators=100, max_samples='auto')
    predictions = model.fit_predict(data)
    print(predictions)
    anomalies = [pkt for i, pkt in enumerate(packets) if predictions[i] == -1]
    logging.info("Anomaly detection completed.")
    return anomalies

def classify_threat(pkt):
    logging.info("Classifying the threat based on packet analysis...")
    flags = pkt.sprintf("%TCP.flags%")

    if "S" in flags and "A" not in flags:
        return "SYN Flood Attack", "Possible Denial-of-Service", "SYN packets sent repeatedly without acknowledgment, common in DoS attacks."
    elif pkt.haslayer(scapy.ICMP) and pkt[scapy.ICMP].type == 8:
        return "ICMP Ping Sweep", "Reconnaissance", "Multiple ICMP echo requests, often a scan to identify active hosts."
    elif pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qdcount > 2:
        return "DNS Amplification", "Potential DDoS via DNS", "Excessive DNS queries indicating potential DDoS attack."
    elif pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
        return "ARP Spoofing", "Man-in-the-Middle", "Spoofed ARP responses attempting to intercept network traffic."
    elif pkt.haslayer(scapy.DNS) and len(pkt[scapy.DNS].qd.qname) > 60:
        return "DNS Tunneling", "Data Exfiltration", "Large DNS query names indicating possible tunneling."
    elif pkt.haslayer(scapy.TCP) and flags in ["F", "S", "R", "P", "U"]:
        return "Port Scan", "Reconnaissance", "Various TCP flags indicating potential probing of network ports."
    elif pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].len == 0:
        return "UDP Flood", "Possible Denial-of-Service", "Numerous empty UDP packets, typical of DoS attacks."
    elif pkt.haslayer(scapy.TCP) and flags == "F":
        return "FIN Scan", "Potential Stealth Scan", "Packets with only the FIN flag set, used to bypass detection."
    else:
        return "Unusual Activity", "Anomalous Packet Behavior", "Unusual packet characteristics detected in the network."


def insert_threat_and_block(ip, threat_type, crime, description):
    logging.info("Inserting threat data for IP %s into database...", ip)
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO network_logs (ip_address, threat_type, user_crime, is_blocked, detected_at) VALUES (%s, %s, %s, %s, %s)",
                (ip, threat_type, crime, 1, datetime.datetime.now())
            )
            conn.commit()
            logging.info("Threat data inserted successfully.")
            block_ip(ip)
        except mysql.connector.Error as err:
            logging.error("Failed to insert threat for IP %s: %s", ip, err)
        finally:
            cursor.close()
            conn.close()

def block_ip(ip):
    logging.info("Blocking IP %s using OS-specific firewall rules...", ip)
    os_type = platform.system()
    try:
        if os_type == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info("IP %s successfully blocked with Linux IPtables.", ip)
        elif os_type == "Windows":
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", "remoteip=" + ip], check=True)
            logging.info("IP %s successfully blocked with Windows firewall.", ip)
        else:
            logging.warning("Unsupported OS for automatic blocking: %s", os_type)
    except subprocess.CalledProcessError as e:
        logging.error("Error blocking IP %s: %s", ip, e)

def main():
    logging.info("Starting network monitoring script.")
    
    # real_time_network_tracker started in a separate thread
    try:
        threading.Thread(target=real_time_network_tracker, daemon=True).start()
        logging.info("Real-time network tracker started successfully.")
    except Exception as e:
        logging.error("Failed to start real-time network tracker: %s", str(e))

    while True:
        check_pid_file()

        parser = argparse.ArgumentParser(description="Network Scanner Script")
        parser.add_argument("action", type=str, help="Action to perform (e.g., 'scan')")
        parser.add_argument("--count", type=int, default=100, help="The number of hosts to scan")

        args = parser.parse_args()
        if args.action.lower() == 'scan':
            scan_subnet(count=args.count)
        else:
            logging.error("Invalid action specified: %s", args.action)
            sys.exit(1)

        time.sleep(1) 

    log_queue.put(None)  
    listener_thread.join()

if __name__ == "__main__":
    main()