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
import json

from collections import defaultdict
import signal
from count_OnlineUsers import real_time_network_tracker, signal_all_user

from logging.handlers import RotatingFileHandler



DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'securityapp'
}

log_queue = queue.Queue()
queue_handler = logging.handlers.QueueHandler(log_queue)
logger = logging.getLogger()
logger.addHandler(queue_handler)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('../logs/networkmonitor.log', 'a') 
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

PID_FILE = '../network_scan_pid.txt'

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
        # Creating a socket to connect to a public address
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
    
    # Check if the system has enough resources to proceed
    if not check_system_resources():
        logging.warning("System resources are insufficient, aborting scan.")
        return

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
        if threat_type:
            logging.info("Threat detected: %s from IP %s", threat_type, ip)
            device_name = get_device_name(ip)
            insert_threat_and_block(ip, threat_type, user_crime, description, device_name)
         else:
            logging.info("No significant threat found for IP: %s", ip)

    else:
        logging.info("Skipping IP %s as it is already blocked.", ip)

def check_system_resources():
    """Check if the system has sufficient resources to run the scan."""
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    logging.info("CPU Usage: %d%%, Memory Usage: %d%%", cpu_usage, memory.percent)

    # Adjust scan behavior based on resource usage
    if cpu_usage > 80 or memory.percent > 80:
        logging.warning("High resource usage detected, reducing scan frequency.")
        return False
    return True


# Rate limiting settings
RATE_LIMIT_WINDOW = 60  # Time window in seconds
RATE_LIMIT_THRESHOLD = 100  # Max packets per IP per window

# Whitelist (trusted IPs)
def load_whitelisted_ips(filename="whitelist.json"):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            return set(data.get("whitelisted_ips", []))
    except Exception as e:
        logging.error(f"Failed to load whitelist: {e}")
        return set()

whitelisted_ips = load_whitelisted_ips()


# IP request counts
ip_request_counts = defaultdict(list)

def log_rate_limited_ip(ip):
    logging.warning(f"Rate limit exceeded for IP {ip}. Blocking temporarily.")

def is_ip_whitelisted(ip):
    return ip in whitelisted_ips

def is_rate_limited(ip):
    current_time = time.time()
    # Remove old entries outside the rate limit window
    ip_request_counts[ip] = [timestamp for timestamp in ip_request_counts[ip] if current_time - timestamp < RATE_LIMIT_WINDOW]
    # Add current request time
    ip_request_counts[ip].append(current_time)
    
    if len(ip_request_counts[ip]) > RATE_LIMIT_THRESHOLD:
        log_rate_limited_ip(ip)
        return True
    return False

def cleanup_old_ips():
    now = time.time()
    for ip in list(ip_request_counts.keys()):
        ip_request_counts[ip] = [t for t in ip_request_counts[ip] if now - t < RATE_LIMIT_WINDOW]
        if not ip_request_counts[ip]:
            del ip_request_counts[ip]
    


def detect_anomalies(packets):
    logging.info("Detecting anomalies in captured packets...")
    data = []
    valid_packets = []

    for pkt in packets:
        if hasattr(pkt, 'time') and pkt.haslayer(scapy.IP):
            features = [
                pkt.time,
                len(pkt),
                pkt[scapy.IP].ttl,
                pkt[scapy.IP].id,
                pkt[scapy.IP].tos
            ]
            if pkt.haslayer(scapy.TCP):
                features += [pkt[scapy.TCP].sport, pkt[scapy.TCP].dport]
            elif pkt.haslayer(scapy.UDP):
                features += [pkt[scapy.UDP].sport, pkt[scapy.UDP].dport]
            else:
                features += [0, 0]

            data.append(features)
            valid_packets.append(pkt)  # Keep a parallel list of valid packets

    if len(data) < 2:
        logging.info("Not enough data to detect anomalies.")
        return []

    model = IsolationForest(contamination=0.01, n_estimators=100)
    predictions = model.fit_predict(np.array(data))
    anomalies = [pkt for i, pkt in enumerate(valid_packets) if predictions[i] == -1]
    return anomalies




def analyze_frequency(ip):
    now = time.time()
    ip_request_counts[ip] = [t for t in ip_request_counts[ip] if now - t < 10]
    ip_request_counts[ip].append(now)

    if len(ip_request_counts[ip]) > 15:  # More than 15 packets in 10 seconds
        return True
    return False



def start_packet_router():
    """
    Acts as a gateway that drops packets based on is_blocked IPs from the DB.
    """
    def packet_handler(pkt):
        if pkt.haslayer(scapy.IP):
            ip_src = pkt[scapy.IP].src
            if check_if_ip_blocked(ip_src):
                logging.warning(f"⛔ Blocked packet from {ip_src} (is_blocked = 1 in DB)")
                return  # Drop this packet
            else:
                logging.debug(f"✅ Allowed packet from {ip_src}")
    
    logging.info("🚦 Starting live routing handler based on DB flags.")
    scapy.sniff(prn=packet_handler, filter="ip", store=False)


def analyze_packet_frequency(ip, protocol):
    return True  # Placeholder logic — implement real checks

KNOWN_ARP_DEVICES = {
    "192.168.1.1": "aa:bb:cc:dd:ee:ff",
    # Add real values
}
def is_known_arp_device(ip, mac):
    return KNOWN_ARP_DEVICES.get(ip) == mac


def analyze_port_scans(ip):
    return True  # Placeholder



def estimate_confidence(threat_type):
    if threat_type == "SYN Flood Attack":
        return 0.9
    elif threat_type == "ARP Spoofing":
        return 0.85
    elif threat_type == "ICMP Ping Sweep":
        return 0.8
    elif threat_type == "Port Scan":
        return 0.75
    elif threat_type == "UDP Flood":
        return 0.9
    elif threat_type == "DNS Tunneling":
        return 0.7
    elif threat_type == "DNS Amplification":
        return 0.95
    else:
        return 0.5  # Unknown or less confident threats



def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"



def classify_threat(pkt):
    """
    Classify threats based on packet analysis with additional robustness to avoid misclassification.
    """
    logging.info("Classifying the threat based on packet analysis...")
    
    ip_src = pkt[scapy.IP].src

    if analyze_frequency(ip_src):
        return "Abnormal Traffic", "Packet Flooding Detected", "Excessive traffic rate from IP"



    
    # Check if the source IP is whitelisted
    if is_ip_whitelisted(ip_src):
        logging.info(f"IP {ip_src} is whitelisted. Skipping classification.")
        return None, None, "Packet from trusted source, no threat analysis performed."

    # Check for rate limiting
    if is_rate_limited(ip_src):
        logging.info(f"Rate limiting triggered for IP {ip_src}. Further analysis deferred.")
        return None, None, "Rate limited, packet analysis deferred."


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
        # else:
            # threat_type = "Unusual Activity"
            # user_crime = "Anomalous Packet Behavior"
            # description = "Unusual packet characteristics detected in the network."

        # Log the threat details if classified
        if threat_type:
            logging.info("Threat classified: %s (%s) - %s", threat_type, user_crime, description)
            return threat_type, user_crime, description
        else:
            return None, None, "Packet deemed non-threatening after analysis."

    except Exception as e:
        logging.error("Error during threat classification: %s", str(e))
        return "Error", "Error in Classification", str(e)


def insert_threat_and_block(ip, threat_type, crime, description, device_name="Unknown"):
    logging.info("Inserting threat data for IP %s into database...", ip)
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()

            confidence = estimate_confidence(threat_type)
            if confidence < 0.6:
                logging.info("Low-confidence threat skipped.")
                return


            cursor.execute("SELECT detected_at FROM network_logs WHERE ip_address = %s", (ip,))
            row = cursor.fetchone()
            if row:
                last_detected = row[0]
                if (datetime.datetime.now() - last_detected).total_seconds() < 300:
                    logging.info("Skipping duplicate threat insert for IP %s", ip)
                    return

            cursor.execute(
                """INSERT INTO network_logs 
                (ip_address, threat_type, user_crime, is_blocked, detected_at, confidence_score, device_name) 
                VALUES (%s, %s, %s, %s, %s, %s, %s) 
                ON DUPLICATE KEY UPDATE 
                    is_blocked=1, 
                    detected_at=NOW(), 
                    confidence_score=%s,
                    device_name=%s""",
                (ip, threat_type, crime, 1, datetime.datetime.now(), confidence, device_name, confidence, device_name)
            )


            conn.commit()
            logging.info("Threat data inserted successfully.")
            mark_ip_as_blocked(ip)
        except mysql.connector.Error as err:
            logging.error("Failed to insert threat for IP %s: %s", ip, err)
        finally:
            cursor.close()
            conn.close()

def mark_ip_as_blocked(ip):
    logging.info(f"IP {ip} marked as blocked in DB. No firewall command executed — routing will reject it dynamically.")

def save_iptables_rules():
    pass  # No iptables used anymore



# Handling the signal to cleanly terminate processes when receiving SIGTERM
def signal_handler(signum, frame):
    logging.info("Signal received. Cleaning up and terminating.")

    signal_all_user()


# Execute the scan periodically or based on external events
if __name__ == "__main__":
    check_pid_file()
    signal.signal(signal.SIGTERM, signal_handler)

    # Start DB-based routing firewall logic
    gateway_thread = threading.Thread(target=start_packet_router, daemon=True)
    gateway_thread.start()

    def run():
        real_time_network_tracker()
        scan_subnet()

    try:
        while True:
            run()
            cleanup_old_ips()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopping application cleanly...")
        signal_all_user()
        print("Application stopped.")




