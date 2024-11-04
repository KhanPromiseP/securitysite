# WebsiteMonitor.py
import requests
import mysql.connector
import logging
import datetime
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict
from contextlib import closing
import platform
import subprocess

# Logging configuration with rotation
logging.basicConfig(filename='website_monitor.log', filemode='a', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'network_monitor'
}

WEBSITES = ['https://github.com', 'https://yourwebsite.com', 'https://another-website.com']
suspicious_ips = set()

def connect_to_db():
    logging.debug("Attempting to connect to the database...")
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        logging.debug("Database connection established.")
        return conn
    except mysql.connector.Error as err:
        logging.error("Database connection error: %s", err)
        return None
    except Exception as e:
        logging.error("An unexpected error occurred: %s", e)
        return None

def log_event(conn, url, status, response_time, issue=None, ip_address=None):
    logging.debug(f"Logging event for URL: {url}, Status: {status}, Response Time: {response_time}, Issue: {issue}, IP: {ip_address}")
    try:
        with closing(conn.cursor()) as cursor:
            cursor.execute(
                "INSERT INTO website_logs (url, status, response_time, issue, ip_address, is_blocked, checked_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (url, status, response_time, issue, ip_address, 1 if ip_address in suspicious_ips else 0, datetime.datetime.now())
            )
            conn.commit()
        logging.debug("Event logged successfully.")
        if ip_address and ip_address in suspicious_ips:
            block_ip(ip_address)
    except mysql.connector.Error as err:
        logging.error("Failed to log event: %s", err)

def monitor_website(url):
    logging.debug(f"Monitoring website: {url}")
    for attempt in range(3):  # Retry logic
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            start_time = time.time()
            response = requests.get(url, timeout=10, headers=headers)
            response_time = round(time.time() - start_time, 3)
            ip_address = response.raw._connection.sock.getpeername()[0]
            logging.debug(f"Website {url} is UP. Response Time: {response_time}, IP: {ip_address}")
            return "UP", response_time, None, ip_address if response.status_code == 200 else f"Unexpected status: {response.status_code}", None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt + 1} failed for {url}. Error: {e}")
            time.sleep(2 ** attempt)  # Exponential backoff
    logging.debug(f"Website {url} is DOWN after 3 attempts.")
    return "DOWN", None, "Request failed after retries", None

def detect_anomalies(response_times):
    logging.debug(f"Detecting anomalies in response times: {response_times}")
    if len(response_times) < 10:
        logging.debug("Not enough data points to detect anomalies.")
        return []
    model = IsolationForest(contamination=0.05)
    predictions = model.fit_predict(np.array(response_times).reshape(-1, 1))
    anomalies = [time for i, time in enumerate(response_times) if predictions[i] == -1]
    logging.debug(f"Anomalies detected: {anomalies}")
    return anomalies

def block_ip(ip):
    logging.debug(f"Attempting to block IP: {ip}")
    os_type = platform.system()
    try:
        if os_type == "Linux":
            # Block IP using iptables on Linux
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info("Blocked IP %s using iptables", ip)
        elif os_type == "Windows":
            # Block IP using Windows firewall
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", "remoteip=" + ip], check=True)
            logging.info("Blocked IP %s using Windows Firewall", ip)
        else:
            logging.warning("Unsupported OS for automatic blocking: %s", os_type)
    except subprocess.CalledProcessError as e:
        logging.error("Error blocking IP %s: %s", ip, e)
def scheduled_monitoring():
    logging.debug("Starting scheduled monitoring...")
    conn = connect_to_db()
    if conn is None:
        logging.error("Database connection could not be established. Exiting scheduled monitoring.")
        return
    response_times_by_url = defaultdict(list)

    for url in WEBSITES:
        logging.debug(f"Monitoring website: {url}")
        status, response_time, issue, ip_address = monitor_website(url)
        if response_time:
            response_times_by_url[url].append(response_time)
        if status == "DOWN" and ip_address:
            suspicious_ips.add(ip_address)
            log_event(conn, url, status, response_time, issue, ip_address)

        # Detect anomalies in response times after logging
        for url, times in response_times_by_url.items():
            anomalies = detect_anomalies(times)
            if anomalies:
                logging.warning(f"Anomalies detected for {url}: {anomalies}")
                for time in anomalies:
                    if ip_address:
                        suspicious_ips.add(ip_address)
                        log_event(conn, url, status, response_time, issue, ip_address)

    if conn:
        logging.debug("Closing database connection.")
        conn.close()
    logging.debug("Scheduled monitoring completed.")

if __name__ == "__main__":
    logging.debug("Starting WebsiteMonitor script.")
    scheduled_monitoring()
    logging.debug("WebsiteMonitor script completed.")
