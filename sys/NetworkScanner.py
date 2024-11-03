import scapy.all as scapy
from sklearn.ensemble import IsolationForest
import mysql.connector
import datetime
import logging
import numpy as np
import sys
import platform
import subprocess

# Setup logging
logging.basicConfig(filename='network_monitor.log', filemode='a', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'network_monitor'
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

def scan_subnet(subnet="192.168.1.0/24"):
    logging.info("Starting subnet scan on %s", subnet)
    packets = scapy.sniff(count=100, filter="ip", timeout=10)
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
    data = np.array([[pkt.time, len(pkt)] for pkt in packets if hasattr(pkt, 'time') and hasattr(pkt, 'len')])
    logging.debug("Data prepared for anomaly detection: %s", data)
    if len(data) < 10:
        logging.warning("Insufficient data (%d samples) for anomaly detection.", len(data))
        return []

    model = IsolationForest(contamination=0.01)
    predictions = model.fit_predict(data)
    anomalies = [pkt for i, pkt in enumerate(packets) if predictions[i] == -1]
    logging.info("Anomaly detection completed. Detected %d anomalies out of %d packets.", len(anomalies), len(packets))
    return anomalies

def classify_threat(pkt):
    logging.debug("Classifying threat for packet with length %d and TTL %d", len(pkt), pkt[scapy.IP].ttl)
    features = [len(pkt), pkt[scapy.IP].ttl]
    if features[0] > 1000:
        return "High Bandwidth Attack", "Suspicious Data Transfer"
    else:
        return "Unusual Activity", "Anomalous Packet Behavior"

def insert_threat_and_block(ip, threat_type, crime):
    logging.info("Inserting threat data for IP %s with threat type: %s and crime: %s", ip, threat_type, crime)
    conn = connect_to_db()
    if conn is not None:
        try:
            cursor = conn.cursor()
            logging.debug("Executing SQL insert for IP %s", ip)
            cursor.execute(
                "INSERT INTO network_logs (ip_address, threat_type, user_crime, is_blocked, detected_at) VALUES (%s, %s, %s, %i, %s)",
                (ip, threat_type, crime, 1, datetime.datetime.now())
            )
            conn.commit()
            logging.info("Threat inserted and blocked for IP %s", ip)
            
            # Block IP after insertion
            block_ip(ip)

        except mysql.connector.Error as err:
            logging.error("Failed to insert threat for IP %s: %s", ip, err)
        finally:
            cursor.close()
            conn.close()
            logging.debug("Database connection closed after inserting threat for IP %s", ip)
    else:
        logging.error("Could not connect to the database to insert threat for IP %s", ip)

def block_ip(ip):
    logging.info("Blocking IP %s", ip)
    os_type = platform.system()
    logging.debug("Detected operating system: %s", os_type)
    
    try:
        if os_type == "Linux":
            logging.debug("Blocking IP %s on Linux using iptables", ip)
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info("Blocked IP %s using iptables", ip)
        elif os_type == "Windows":
            logging.debug("Blocking IP %s on Windows using netsh", ip)
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", "remoteip=" + ip], check=True)
            logging.info("Blocked IP %s using Windows Firewall", ip)
        else:
            logging.warning("Unsupported OS for automatic blocking: %s", os_type)
    except subprocess.CalledProcessError as e:
        logging.error("Error blocking IP %s: %s", ip, e)

def main():
    logging.info("Starting network monitoring script.")
    if len(sys.argv) < 2:
        logging.error("No action specified. Usage: <script> <action>")
        sys.exit(1)

    action = sys.argv[1].lower()
    logging.debug("Action specified: %s", action)
    if action == 'scan':
        scan_subnet()
    else:
        logging.error("Invalid action specified: %s", action)
        sys.exit(1)

if __name__ == "__main__":
    main()
