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
import atexit
import signal
import os
from functools import lru_cache
from collections import defaultdict
from count_OnlineUsers import real_time_network_tracker, signal_all_user
from network_limiter import NetworkLimiter
from logging.handlers import RotatingFileHandler
from config import running

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'securityapp'
}

# LOGGING SYSTEM CONFIGURATION
log_dir = '/opt/lampp/htdocs/securitysite/logs'
os.makedirs(log_dir, exist_ok=True)

log_queue = queue.Queue(-1)
queue_handler = logging.handlers.QueueHandler(log_queue)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
for handler in logger.handlers[:]:
    logger.removeHandler(handler)
logger.addHandler(queue_handler)

file_handler = logging.FileHandler(
    filename=os.path.join(log_dir, 'networkmonitor.log'),
    mode='a',
    encoding='utf-8'
)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

def log_listener():
    while True:
        try:
            record = log_queue.get()
            if record is None:
                break
            file_handler.handle(record)
            log_queue.task_done()
        except Exception as e:
            print(f"CRITICAL LOGGING ERROR: {e}", file=sys.stderr)

listener_thread = threading.Thread(target=log_listener, daemon=True)
listener_thread.start()

def shutdown_logging():
    log_queue.put(None)
    listener_thread.join(timeout=5)
    file_handler.close()
    logging.shutdown()

atexit.register(shutdown_logging)

PID_FILE = '/opt/lampp/htdocs/securitysite/network_scan_pid.txt'

def check_pid_file():
    """Ensure only one instance of the script is running."""
    pid = str(os.getpid())
    if os.path.exists(PID_FILE):
        with open(PID_FILE, 'r') as f:
            old_pid = f.read().strip()
        if os.path.exists(f"/proc/{old_pid}"):
            print(f"⚠️ Another instance is already running (PID: {old_pid})")
            sys.exit(1)
    with open(PID_FILE, 'w') as f:
        f.write(pid)
    logging.info(f"Created PID file with PID: {pid}")

def connect_to_db():
    try:
        logging.info("Attempting to connect to the database...")
        conn = mysql.connector.connect(**DB_CONFIG)
        logging.info("Database connection successful.")
        return conn
    except mysql.connector.Error as err:
        logging.error("Database connection error: %s", err)
        return None

@lru_cache(maxsize=1000)
def scapy_blocker(ip):
    def drop_packet(pkt):
        if pkt.haslayer(scapy.IP) and pkt[scapy.IP].src == ip:
            return False
    try:
        scapy.sniff(prn=drop_packet, store=False, quiet=True, stop_filter=lambda p: not running, timeout=1)
    except Exception as e:
        logging.error(f"Scapy sniff error in scapy_blocker: {e}")

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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        logging.info("Local machine IP detected: %s", local_ip)
        return local_ip
    except socket.error as e:
        logging.error("Unable to retrieve local IP: %s", e)
        return None

def scan_subnet(count=100):
    logging.info("Scanning local subnet for suspicious activity...")
    if not check_system_resources():
        logging.warning("System resources are insufficient, aborting scan.")
        return
    subnet = get_network_details()
    if subnet is None:
        logging.error("Could not retrieve subnet details.")
        return
    local_ip = get_local_ip()
    try:
        packets = scapy.sniff(count=count, filter="ip or tcp or udp or icmp", timeout=15)
        logging.info("Packets captured: %d", len(packets))
        anomalies = detect_anomalies(packets)
        logging.info("Anomalies detected: %d", len(anomalies))
        for pkt in anomalies:
            ip = pkt[scapy.IP].src
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
    except Exception as e:
        logging.error(f"Error in scan_subnet: {e}")

def check_system_resources():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    logging.info("CPU Usage: %d%%, Memory Usage: %d%%", cpu_usage, memory.percent)
    if cpu_usage > 80 or memory.percent > 80:
        logging.warning("High resource usage detected, reducing scan frequency.")
        return False
    return True

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_THRESHOLD = 100
ip_request_counts = defaultdict(list)

def load_whitelisted_ips(filename="whitelist.json"):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            return set(data.get("whitelisted_ips", []))
    except Exception as e:
        logging.error(f"Failed to load whitelist: {e}")
        return set()

whitelisted_ips = load_whitelisted_ips()

def log_rate_limited_ip(ip):
    logging.warning(f"Rate limit exceeded for IP {ip}. Blocking temporarily.")

def is_ip_whitelisted(ip):
    return ip in whitelisted_ips

def is_rate_limited(ip):
    current_time = time.time()
    ip_request_counts[ip] = [timestamp for timestamp in ip_request_counts[ip] if current_time - timestamp < RATE_LIMIT_WINDOW]
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
            valid_packets.append(pkt)
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
    if len(ip_request_counts[ip]) > 15:
        return True
    return False

def start_packet_router():
    def packet_handler(pkt):
        if not running:
            return
        if pkt.haslayer(scapy.IP):
            ip_src = pkt[scapy.IP].src
            if check_if_ip_blocked(ip_src):
                logging.warning(f"Blocked packet from {ip_src} (is_blocked = 1 in DB)")
                return
            else:
                logging.debug(f"Allowed packet from {ip_src}")
    logging.info("🚦 Starting live routing handler based on DB flags.")
    while running:
        try:
            scapy.sniff(prn=packet_handler, filter="ip", store=False, timeout=1, stop_filter=lambda p: not running)
        except Exception as e:
            logging.error(f"Scapy sniff error in start_packet_router: {e}")
            if not running:
                break

def analyze_packet_frequency(ip, protocol):
    return True

def is_known_arp_device(ip, mac):
    KNOWN_ARP_DEVICES = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}
    return KNOWN_ARP_DEVICES.get(ip) == mac

def analyze_port_scans(ip):
    return True

def estimate_confidence(threat_type):
    threats = {
        "SYN Flood Attack": 0.9,
        "ARP Spoofing": 0.85,
        "ICMP Ping Sweep": 0.8,
        "Port Scan": 0.75,
        "UDP Flood": 0.9,
        "DNS Tunneling": 0.7,
        "DNS Amplification": 0.95
    }
    return threats.get(threat_type, 0.5)

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def classify_threat(pkt):
    logging.info("Classifying the threat based on packet analysis...")
    ip_src = pkt[scapy.IP].src
    if analyze_frequency(ip_src):
        return "Abnormal Traffic", "Packet Flooding Detected", "Excessive traffic rate from IP"
    if is_ip_whitelisted(ip_src):
        logging.info(f"IP {ip_src} is whitelisted. Skipping classification.")
        return None, None, "Packet from trusted source, no threat analysis performed."
    if is_rate_limited(ip_src):
        logging.info(f"Rate limiting triggered for IP {ip_src}. Further analysis deferred.")
        return None, None, "Rate limited, packet analysis deferred."
    flags = pkt.sprintf("%TCP.flags%") if pkt.haslayer(scapy.TCP) else None
    try:
        if flags and "S" in flags and "A" not in flags and pkt.haslayer(scapy.TCP):
            if analyze_packet_frequency(pkt[scapy.IP].src, "SYN"):
                return "SYN Flood Attack", "Possible Denial-of-Service", "SYN packets sent repeatedly without acknowledgment, common in DoS attacks."
        elif pkt.haslayer(scapy.ICMP) and pkt[scapy.ICMP].type == 8:
            if analyze_packet_frequency(pkt[scapy.IP].src, "ICMP"):
                return "ICMP Ping Sweep", "Reconnaissance", "Multiple ICMP echo requests, often a scan to identify active hosts."
        elif pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qdcount > 2:
            if analyze_packet_frequency(pkt[scapy.IP].src, "DNS"):
                return "DNS Amplification", "Potential DDoS via DNS", "Excessive DNS queries indicating potential DDoS attack."
        elif pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
            if not is_known_arp_device(pkt[scapy.ARP].psrc, pkt[scapy.ARP].hwsrc):
                return "ARP Spoofing", "Man-in-the-Middle", "Spoofed ARP responses attempting to intercept network traffic."
        elif pkt.haslayer(scapy.DNS) and len(pkt[scapy.DNS].qd.qname) > 60:
            return "DNS Tunneling", "Data Exfiltration", "Large DNS query names indicating possible tunneling."
        elif pkt.haslayer(scapy.TCP) and flags in ["F", "S", "R", "P", "U"]:
            if analyze_port_scans(pkt[scapy.IP].src):
                return "Port Scan", "Reconnaissance", "Various TCP flags indicating potential probing of network ports."
        elif pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].len == 0:
            if analyze_packet_frequency(pkt[scapy.IP].src, "UDP"):
                return "UDP Flood", "Possible Denial-of-Service", "Numerous empty UDP packets, typical of DoS attacks."
        elif pkt.haslayer(scapy.TCP) and flags == "F":
            if analyze_packet_frequency(pkt[scapy.IP].src, "FIN"):
                return "FIN Scan", "Potential Stealth Scan", "Packets with only the FIN flag set, used to bypass detection."
        return None, None, "Packet deemed non-threatening after analysis."
    except Exception as e:
        logging.error(f"Error during threat classification: {e}")
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
            if row and (datetime.datetime.now() - row[0]).total_seconds() < 300:
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
            logging.error(f"Failed to insert threat for IP %s: {err}")
        finally:
            cursor.close()
            conn.close()

def mark_ip_as_blocked(ip):
    try:
        check_cmd = ["iptables", "-C", "SECURITYAPP_BLOCK", "-s", ip, "-j", "DROP"]
        add_cmd = ["iptables", "-A", "SECURITYAPP_BLOCK", "-s", ip, "-j", "DROP"]
        if subprocess.run(check_cmd, stderr=subprocess.DEVNULL).returncode != 0:
            subprocess.run(add_cmd, check=True)
            logging.info(f"Added block rule for {ip}")
        threading.Thread(
            target=lambda: scapy.sniff(
                prn=lambda p: None if (scapy.IP in p and p[scapy.IP].src == ip) else p,
                store=False,
                quiet=True,
                stop_filter=lambda p: not running,
                timeout=1
            ),
            daemon=True
        ).start()
    except Exception as e:
        logging.error(f"Block failed for {ip}: {str(e)}")
        scapy_blocker(ip)

def load_kernel_modules():
    modules = ["ip_tables", "iptable_filter", "x_tables"]
    for mod in modules:
        try:
            subprocess.run(["modprobe", mod], check=True)
        except subprocess.CalledProcessError:
            logging.warning(f"Couldn't load {mod}, some features may fail")

def start_network_limiter():
    """Start the network limiter in a separate thread"""
    limiter = NetworkLimiter()
    limiter_thread = threading.Thread(target=limiter.run, daemon=False)
    limiter_thread.start()
    return limiter_thread

if __name__ == "__main__":
    print("Starting Network Security Monitor...")
    print("Press Ctrl+C to stop")

    threads = []
    def print_status():
        while running:
            print("Running - Monitoring network traffic", end='\r')
            time.sleep(1)
        print(" " * 50, end='\r')

    def shutdown():
        global running
        if not running:
            return
        running = False
        print("\nShutting down gracefully...")
        signal_all_user()
        cleanup_commands = [
            ["iptables", "-D", "INPUT", "-j", "SECURITYAPP_BLOCK"],
            ["iptables", "-D", "FORWARD", "-j", "SECURITYAPP_BLOCK"],
            ["iptables", "-F", "SECURITYAPP_BLOCK"],
            ["iptables", "-X", "SECURITYAPP_BLOCK"]
        ]
        for cmd in cleanup_commands:
            subprocess.run(cmd, stderr=subprocess.DEVNULL)
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
            logging.info("Removed PID file")
        for t in threads:
            t.join(timeout=2)
        shutdown_logging()
        logging.info("Clean shutdown completed")

    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown")
        shutdown()
        threading.Timer(5.0, lambda: os._exit(1)).start()  # Force exit after 5 seconds

    atexit.register(shutdown)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    load_kernel_modules()

    firewall_init_commands = [
        ["iptables", "-N", "SECURITYAPP_BLOCK"],
        ["iptables", "-F", "SECURITYAPP_BLOCK"],
        ["iptables", "-I", "INPUT", "-j", "SECURITYAPP_BLOCK"],
        ["iptables", "-I", "FORWARD", "-j", "SECURITYAPP_BLOCK"]
    ]
    for cmd in firewall_init_commands:
        try:
            result = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=5, text=True)
            if result.returncode != 0:
                logger.error(f"Firewall command failed: {' '.join(cmd)} - {result.stderr}")
            else:
                logger.info(f"Firewall command succeeded: {' '.join(cmd)}")
        except Exception as e:
            logger.error(f"Firewall command failed: {' '.join(cmd)} - {str(e)}")

    check_pid_file()

    gateway_thread = threading.Thread(target=start_packet_router, daemon=False)
    gateway_thread.start()
    threads.append(gateway_thread)
    limiter_thread = start_network_limiter()
    threads.append(limiter_thread)
    status_thread = threading.Thread(target=print_status, daemon=False)
    status_thread.start()
    threads.append(status_thread)

    try:
        while running:
            real_time_network_tracker()
            scan_subnet()
            cleanup_old_ips()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received.")
        shutdown()
    except Exception as e:
        logger.error(f"Fatal error in main loop: {e}")
        shutdown()
        os._exit(1)