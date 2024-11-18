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
import socket

logging.basicConfig(filename='../logs/website_monitor.log', filemode='a', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'security_app'
}

WEBSITES = ['https://github.com']
suspicious_ips = set()

def connect_to_db():
    logging.debug("Attempting to establish database connection...")
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        logging.info("Database connection established successfully.")
        return conn
    except mysql.connector.Error as err:
        logging.error("Database connection error: %s", err)
        return None

def log_event(conn, url, status, response_time, issue, ip_address, is_blocked):
    logging.debug(f"Logging event - URL: {url}, Status: {status}, Response Time: {response_time}, Issue: {issue}, IP: {ip_address}, Blocked: {is_blocked}")
    try:
        with closing(conn.cursor()) as cursor:
            cursor.execute(
                "INSERT INTO website_logs (url, status, response_time, issue, ip_address, is_blocked, checked_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (url, status, response_time, issue, ip_address, is_blocked, datetime.datetime.now())
            )
            conn.commit()
        logging.info("Event logged successfully for URL: %s", url)
    except mysql.connector.Error as err:
        logging.error("Failed to log event for URL %s: %s", url, err)

def monitor_website(url):
    logging.info(f"Starting monitoring for URL: {url}")
    for attempt in range(3):  
        logging.debug(f"Attempt {attempt + 1} for monitoring URL: {url}")
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            start_time = time.time()
            response = requests.get(url, timeout=10, headers=headers)
            response_time = round(time.time() - start_time, 3)
            ip_address = socket.gethostbyname(requests.utils.urlparse(url).netloc)
            logging.info(f"Website {url} is UP. Response Time: {response_time} seconds. IP Address: {ip_address}")
            return ("UP", response_time, None, ip_address)
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt + 1} failed for URL {url}. Error: {e}")
            time.sleep(2 ** attempt)  
    logging.error(f"Website {url} is DOWN after 3 attempts.")
    return ("DOWN", None, "Request failed after retries", None)

def detect_anomalies(response_times):
    logging.debug("Starting anomaly detection on response times: %s", response_times)
    if len(response_times) < 2:
        logging.warning("Insufficient data points for anomaly detection.")
        return []
    model = IsolationForest(contamination=0.05)
    predictions = model.fit_predict(np.array(response_times).reshape(-1, 1))
    anomalies = [time for i, time in enumerate(response_times) if predictions[i] == -1]
    logging.info(f"Anomalies detected: {anomalies}")
    return anomalies

def block_ip(ip):
    logging.info(f"Attempting to block IP: {ip}")
    os_type = platform.system()
    try:
        if os_type == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info("Blocked IP %s using iptables on Linux", ip)
        elif os_type == "Windows":
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", "remoteip=" + ip], check=True)
            logging.info("Blocked IP %s using Windows Firewall", ip)
        else:
            logging.warning("Unsupported OS for automatic blocking: %s", os_type)
    except subprocess.CalledProcessError as e:
        logging.error("Failed to block IP %s: %s", ip, e)

def scheduled_monitoring():
    logging.debug("Starting scheduled monitoring session...")
    conn = connect_to_db()
    if conn is None:
        logging.critical("Database connection failed. Scheduled monitoring will not proceed.")
        return

    response_times_by_url = defaultdict(list)

    for url in WEBSITES:
        logging.debug(f"Processing URL: {url}")
        status, response_time, issue, ip_address = monitor_website(url)
        
        if response_time:
            response_times_by_url[url].append(response_time)

        anomalies = detect_anomalies(response_times_by_url[url])
        
        if anomalies:
            logging.warning(f"Anomalies detected for URL {url}: {anomalies}")
            issue = "Anomalous response time detected"
            suspicious_ips.add(ip_address)
            log_event(conn, url, status, response_time, issue, ip_address, 1)
            block_ip(ip_address)
        else:
            log_event(conn, url, status, response_time, issue, ip_address, 0)

    if conn:
        logging.debug("Closing database connection.")
        conn.close()
    logging.info("Scheduled monitoring session completed.")

if __name__ == "__main__":
    logging.info("WebsiteMonitor script initiated.")
    scheduled_monitoring()
    logging.info("WebsiteMonitor script finished.")
