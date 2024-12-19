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

def get_local_ip():
    """Retrieve the local machine's primary IP address (to avoid accidental blocking)."""
    try:
        # Create a socket to connect to a public address
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Using Google's public DNS server (8.8.8.8) to determine the primary IP
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        logging.info("Local machine IP detected: %s", local_ip)
        return local_ip
    except socket.error as e:
        logging.error("Unable to retrieve local IP: %s", e)
        return None


def scan_subnet(count=100):
    logging.info("Scanning local subnet for suspicious activity...")
    subnet = get_network_details()
    if subnet is None:
        logging.error("Could not retrieve subnet details.")
        return

    local_ip = get_local_ip()  # Get the local machine's IP for exclusion
    packets = scapy.sniff(count=count, filter="ip or tcp or udp or icmp", timeout=15)
    logging.info("Packets captured: %d", len(packets))
    anomalies = detect_anomalies(packets)
    logging.info("Anomalies detected: %d", len(anomalies))

    for pkt in anomalies:
        ip = pkt[scapy.IP].src

        # Exclude local IP from being flagged or blocked
        if ip == local_ip:
            logging.info("Skipping local machine IP: %s", ip)
            continue

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
    """
    Classify threats based on packet analysis with additional robustness to avoid misclassification.
    """
    logging.info("Classifying the threat based on packet analysis...")
    
    # Check for the TCP flags in the packet
    flags = pkt.sprintf("%TCP.flags%") if pkt.haslayer(scapy.TCP) else None
    threat_type = None
    user_crime = None
    description = None

    # Adding multiple checks for more precise classification
    try:
        # SYN Flood Attack: Multiple SYN packets without acknowledgment within a short time
        if flags and "S" in flags and "A" not in flags and pkt.haslayer(scapy.TCP):
            #IP address is Only classify as SYN Flood if the packet count exceeds a threshold
            if analyze_packet_frequency(pkt[scapy.IP].src, "SYN"):
                threat_type = "SYN Flood Attack"
                user_crime = "Possible Denial-of-Service"
                description = "SYN packets sent repeatedly without acknowledgment, common in DoS attacks."

        # ICMP Ping Sweep: Only classify if there are repeated pings from the same source
        elif pkt.haslayer(scapy.ICMP) and pkt[scapy.ICMP].type == 8:
            if analyze_packet_frequency(pkt[scapy.IP].src, "ICMP"):
                threat_type = "ICMP Ping Sweep"
                user_crime = "Reconnaissance"
                description = "Multiple ICMP echo requests, often a scan to identify active hosts."

        # DNS Amplification: Focus on excessive query counts and repeated patterns
        elif pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qdcount > 2:
            if analyze_packet_frequency(pkt[scapy.IP].src, "DNS"):
                threat_type = "DNS Amplification"
                user_crime = "Potential DDoS via DNS"
                description = "Excessive DNS queries indicating potential DDoS attack."

        # ARP Spoofing: Validate against legitimate devices on the network
        elif pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
            if not is_known_arp_device(pkt[scapy.ARP].psrc, pkt[scapy.ARP].hwsrc):
                threat_type = "ARP Spoofing"
                user_crime = "Man-in-the-Middle"
                description = "Spoofed ARP responses attempting to intercept network traffic."

        # DNS Tunneling: Check for abnormally large DNS query names
        elif pkt.haslayer(scapy.DNS) and len(pkt[scapy.DNS].qd.qname) > 60:
            threat_type = "DNS Tunneling"
            user_crime = "Data Exfiltration"
            description = "Large DNS query names indicating possible tunneling."

        # Port Scan: Correlate multiple probes to classify as a scan
        elif pkt.haslayer(scapy.TCP) and flags in ["F", "S", "R", "P", "U"]:
            if analyze_port_scans(pkt[scapy.IP].src):
                threat_type = "Port Scan"
                user_crime = "Reconnaissance"
                description = "Various TCP flags indicating potential probing of network ports."

        # UDP Flood: Check for excessive empty UDP packets
        elif pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].len == 0:
            if analyze_packet_frequency(pkt[scapy.IP].src, "UDP"):
                threat_type = "UDP Flood"
                user_crime = "Possible Denial-of-Service"
                description = "Numerous empty UDP packets, typical of DoS attacks."

        # FIN Scan: Only classify if repeated behavior is detected
        elif pkt.haslayer(scapy.TCP) and flags == "F":
            if analyze_packet_frequency(pkt[scapy.IP].src, "FIN"):
                threat_type = "FIN Scan"
                user_crime = "Potential Stealth Scan"
                description = "Packets with only the FIN flag set, used to bypass detection."

        # Fallback: Mark as unusual activity with minimal certainty
        else:
            threat_type = "Unusual Activity"
            user_crime = "Anomalous Packet Behavior"
            description = "Unusual packet characteristics detected in the network."

        # Log the threat details if classified
        if threat_type:
            logging.info("Threat classified: %s (%s) - %s", threat_type, user_crime, description)
            return threat_type, user_crime, description
        else:
            return None, None, "Packet deemed non-threatening after analysis."

    except Exception as e:
        logging.error("Error during threat classification: %s", str(e))
        return "Error", "Error in Classification", str(e)




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
            # Block the IP using iptables
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info("IP %s successfully blocked with Linux IPtables.", ip)
            # Save the rules to a file
            save_iptables_rules()
        elif os_type == "Windows":
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", "remoteip=" + ip], check=True)
            logging.info("IP %s successfully blocked with Windows firewall.", ip)
        else:
            logging.warning("Unsupported OS for automatic blocking: %s", os_type)
    except subprocess.CalledProcessError as e:
        logging.error("Error blocking IP %s: %s", ip, e)
def save_iptables_rules():
    rules_file = "/etc/iptables/rules.v4"
    try:
        os.makedirs(os.path.dirname(rules_file), exist_ok=True)
        subprocess.run(["sudo", "iptables-save"], stdout=open(rules_file, "w"), check=True)
        logging.info("iptables rules saved successfully to %s.", rules_file)
    except Exception as e:
        logging.error("Failed to save iptables rules: %s", str(e))


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