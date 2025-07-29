#!/usr/bin/env python3
import os
import subprocess
import time
import threading
import signal
import logging
from logging.handlers import RotatingFileHandler
from scapy.all import ARP, Ether, srp, sniff
from scapy.layers.inet import IP
import netifaces
import mysql.connector
from datetime import datetime, timedelta
import socket
import json
import re
from dataclasses import dataclass
from typing import Dict, Set, Optional, Tuple, List
from functools import lru_cache
import sys
from threading import Lock
from collections import defaultdict

# Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'securityapp',
    'ssl_disabled': True,  # Disable SSL to avoid HTTPS errors
    'connect_timeout': 10  # Increase timeout
}

SCAN_INTERVAL = 1  # Reduced from 2 seconds
PID_FILE = '/opt/lampp/htdocs/securitysite/network_tracker_pid.txt'
BANDWIDTH_LIMIT = "32kbit"
BANDWIDTH_BURST = "64kbit"

# Global running flag
running = True

# Thread-safe data structures
traffic_data = defaultdict(lambda: {
    'in_bytes': 0, 
    'out_bytes': 0, 
    'in_pkts': 0, 
    'out_pkts': 0
})
mac_ip_mapping = {}
data_lock = Lock()
mapping_lock = Lock()
current_subnet = None

@dataclass
class DeviceStats:
    mac: str
    ip: str
    hostname: str
    data_usage_mb: float
    last_seen: datetime
    connection_count: int
    status: str
    is_permanent: bool

class TrafficMonitor:
    def __init__(self):
        self.logger = logging.getLogger('TrafficMonitor')
        self.last_counter_values = defaultdict(lambda: {'in_bytes': 0, 'out_bytes': 0, 'in_pkts': 0, 'out_pkts': 0})
        self.packet_counts = defaultdict(lambda: {'in_bytes': 0, 'out_bytes': 0, 'in_pkts': 0, 'out_pkts': 0})
        self.interface, _ = get_interface_details()
        self.ensure_accounting_setup()
        self.start_packet_sniffing()

    def ensure_accounting_setup(self):
        try:
            subprocess.run(["nft", "list", "table", "inet", "traffic_accounting"], 
                         stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            self.logger.debug("nftables traffic_accounting table exists")
        except subprocess.CalledProcessError:
            try:
                subprocess.run(["nft", "add", "table", "inet", "traffic_accounting"], check=True)
                subprocess.run([
                    "nft", "add", "chain", "inet", "traffic_accounting", "input_chain",
                    "{ type filter hook input priority raw ; policy accept ; }"
                ], check=True)
                subprocess.run([
                    "nft", "add", "chain", "inet", "traffic_accounting", "output_chain",
                    "{ type filter hook output priority raw ; policy accept ; }"
                ], check=True)
                self.logger.info("Created nftables accounting setup")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Accounting setup failed: {e.stderr.decode()}")
                raise

    def update_device_rules(self, devices: List[Tuple[str, str, str]]):
        try:
            subprocess.run(["nft", "flush", "table", "inet", "traffic_accounting"], 
                         stderr=subprocess.DEVNULL, check=True)
            subprocess.run(["nft", "add", "table", "inet", "traffic_accounting"], check=True)
            subprocess.run([
                "nft", "add", "chain", "inet", "traffic_accounting", "input_chain",
                "{ type filter hook input priority raw ; policy accept ; }"
            ], check=True)
            subprocess.run([
                "nft", "add", "chain", "inet", "traffic_accounting", "output_chain",
                "{ type filter hook output priority raw ; policy accept ; }"
            ], check=True)
            with mapping_lock:
                mac_ip_mapping.clear()
                for ip, mac, _ in devices:
                    mac = mac.lower()
                    if not self.validate_mac(mac) or not self.validate_ip(ip):
                        self.logger.warning(f"Invalid MAC {mac} or IP {ip}, skipping")
                        continue
                    mac_ip_mapping[mac] = ip
                    subprocess.run([
                        "nft", "add", "rule", "inet", "traffic_accounting", "input_chain",
                        f"ether saddr {mac} counter"
                    ], check=True)
                    subprocess.run([
                        "nft", "add", "rule", "inet", "traffic_accounting", "output_chain",
                        f"ip daddr {ip} counter"
                    ], check=True)
            self.logger.info(f"Updated traffic rules for {len(mac_ip_mapping)} devices")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Rule update failed: {e.stderr.decode() if e.stderr else str(e)}")

    def validate_mac(self, mac: str) -> bool:
        return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac))

    def validate_ip(self, ip: str) -> bool:
        try:
            socket.inet_aton(ip)
            return ip != "0.0.0.0" and not ip.startswith("169.254.")
        except socket.error:
            return False

    def collect_traffic_stats(self):
        stats = defaultdict(lambda: {'in_bytes': 0, 'out_bytes': 0, 'in_pkts': 0, 'out_pkts': 0})
        success = False
        try:
            result = subprocess.run(
                ["nft", "-j", "list", "table", "inet", "traffic_accounting"],
                capture_output=True, text=True, check=True
            )
            data = json.loads(result.stdout)
            for item in data.get('nftables', []):
                if 'rule' not in item:
                    continue
                rule = item['rule']
                if 'counter' not in rule:
                    continue
                bytes_val = int(rule['counter']['bytes'])
                pkts_val = int(rule['counter']['packets'])
                for expr in rule.get('expr', []):
                    if not isinstance(expr, dict) or 'match' not in expr:
                        continue
                    match = expr['match']
                    left = match.get('left', {})
                    if isinstance(left, dict) and left.get('payload', {}).get('field') == 'saddr':
                        mac = match['right'].lower().replace('"', '').replace("'", "")
                        stats[mac]['in_bytes'] = bytes_val
                        stats[mac]['in_pkts'] = pkts_val
                    elif isinstance(left, dict) and left.get('payload', {}).get('field') == 'daddr':
                        ip = match['right'].replace('"', '').replace("'", "")
                        with mapping_lock:
                            mac = next((m for m, i in mac_ip_mapping.items() if i == ip), None)
                        if mac:
                            stats[mac]['out_bytes'] = bytes_val
                            stats[mac]['out_pkts'] = pkts_val
            success = True
            self.logger.debug(f"Collected nftables traffic for {len(stats)} devices")
        except Exception as e:
            self.logger.warning(f"nftables traffic collection failed: {str(e)}")
        if not success:
            try:
                iface = self.interface
                result = subprocess.run(["ip", "-s", "link", "show", iface], 
                                     capture_output=True, text=True, check=True)
                lines = result.stdout.splitlines()
                for i, line in enumerate(lines):
                    if "RX:" in line:
                        rx_stats = lines[i+1].strip().split()
                        tx_stats = lines[i+3].strip().split()
                        with mapping_lock:
                            for mac, ip in mac_ip_mapping.items():
                                stats[mac]['in_bytes'] += int(rx_stats[0])
                                stats[mac]['in_pkts'] += int(rx_stats[1])
                                stats[mac]['out_bytes'] += int(tx_stats[0])
                                stats[mac]['out_pkts'] += int(tx_stats[1])
                success = True
                self.logger.debug(f"Collected iproute2 traffic for {len(stats)} devices")
            except Exception as e:
                self.logger.warning(f"iproute2 traffic collection failed: {str(e)}")
        with data_lock:
            for mac, new_stats in stats.items():
                if mac not in traffic_data:
                    traffic_data[mac] = {'in_bytes': 0, 'out_bytes': 0, 'in_pkts': 0, 'out_pkts': 0}
                if mac not in self.last_counter_values:
                    self.last_counter_values[mac] = {'in_bytes': 0, 'out_bytes': 0, 'in_pkts': 0, 'out_pkts': 0}
                for key in ['in_bytes', 'out_bytes', 'in_pkts', 'out_pkts']:
                    current = new_stats[key]
                    last = self.last_counter_values[mac][key]
                    delta = current - last if current >= last else current
                    if delta > 0:
                        traffic_data[mac][key] += delta
                    self.last_counter_values[mac][key] = current
            if success:
                self.logger.debug(f"Aggregated traffic for {len(stats)} devices")
            else:
                self.logger.error("All traffic collection methods failed")

    def start_packet_sniffing(self):
        def packet_handler(packet):
            try:
                if packet.haslayer(Ether) and packet.haslayer(IP):
                    src_mac = packet[Ether].src.lower()
                    dst_ip = packet[IP].dst
                    pkt_size = len(packet)
                    with mapping_lock:
                        mac = src_mac if src_mac in mac_ip_mapping else next((m for m, i in mac_ip_mapping.items() if i == dst_ip), None)
                    if mac:
                        with data_lock:
                            self.packet_counts[mac]['in_bytes'] += pkt_size
                            self.packet_counts[mac]['in_pkts'] += 1
                            if dst_ip == mac_ip_mapping.get(mac):
                                self.packet_counts[mac]['out_bytes'] += pkt_size
                                self.packet_counts[mac]['out_pkts'] += 1
            except Exception as e:
                self.logger.error(f"Packet sniffing error: {str(e)}")
        try:
            threading.Thread(target=lambda: sniff(iface=self.interface, filter="ip", prn=packet_handler, store=False, stop_filter=lambda _: not running), daemon=True).start()
            self.logger.info("Started scapy packet sniffing")
        except Exception as e:
            self.logger.error(f"Failed to start scapy sniffing: {str(e)}")

class NetworkEnforcer:
    def __init__(self):
        self.blocked_macs: Set[str] = set()
        self.device_stats: Dict[str, DeviceStats] = {}
        self.traffic_monitor = TrafficMonitor()
        self.setup_logging()
        self.setup_persistent_nftables()
        self.network_monitor_thread = threading.Thread(target=self.monitor_network_status, daemon=True)
        self.traffic_thread = threading.Thread(target=self.collect_traffic_periodically, daemon=True)
        self.network_monitor_thread.start()
        self.traffic_thread.start()

    def setup_logging(self):
        log_dir = '/opt/lampp/htdocs/securitysite/logs'
        os.makedirs(log_dir, exist_ok=True)
        log_handler = RotatingFileHandler(
            f'{log_dir}/network_enforcer.log',
            maxBytes=10*1024*1024,
            backupCount=5
        )
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] [%(module)s:%(funcName)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger = logging.getLogger('NetworkEnforcer')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(log_handler)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_handler.formatter)
        self.logger.addHandler(console_handler)

    def setup_persistent_nftables(self):
        try:
            subprocess.run(["nft", "list", "table", "inet", "mac_filter"], 
                         stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            self.logger.debug("nftables mac_filter table exists")
        except subprocess.CalledProcessError:
            try:
                subprocess.run(["nft", "add", "table", "inet", "mac_filter"], check=True)
                subprocess.run([
                    "nft", "add", "chain", "inet", "mac_filter", "input",
                    "{ type filter hook input priority -100 ; policy accept ; }"
                ], check=True)
                subprocess.run([
                    "nft", "add", "chain", "inet", "mac_filter", "forward",
                    "{ type filter hook forward priority -100 ; policy accept ; }"
                ], check=True)
                subprocess.run([
                    "nft", "add", "set", "inet", "mac_filter", "blocked_macs",
                    "{ type ether_addr ; flags dynamic ; }"
                ], check=True)
                subprocess.run([
                    "nft", "add", "rule", "inet", "mac_filter", "input",
                    "ether saddr @blocked_macs drop"
                ], check=True)
                subprocess.run([
                    "nft", "add", "rule", "inet", "mac_filter", "forward",
                    "ether saddr @blocked_macs drop"
                ], check=True)
                subprocess.run(["nft", "list", "ruleset"], stdout=open("/etc/nftables.conf", "w"), check=True)
                subprocess.run(["systemctl", "enable", "nftables"], check=True)
                subprocess.run(["systemctl", "restart", "nftables"], check=True)
                self.logger.info("Persistent nftables configured successfully")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"nftables setup failed: {e.stderr.decode()}")
                raise

    def block_mac(self, mac: str, ip: str = None, reason: str = "Disconnected") -> bool:
        try:
            mac = mac.lower()
            if not self.traffic_monitor.validate_mac(mac):
                self.logger.error(f"Invalid MAC address: {mac}")
                return False
            subprocess.run([
                "nft", "add", "element", "inet", "mac_filter", "blocked_macs",
                f"{{ {mac} }}"
            ], check=True)
            if ip and self.traffic_monitor.validate_ip(ip):
                iface = self.traffic_monitor.interface
                subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], 
                             stderr=subprocess.DEVNULL, check=False)
                subprocess.run(["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb"], 
                             check=True)
                subprocess.run(["tc", "class", "add", "dev", iface, "parent", "1:", 
                               "classid", "1:1", "htb", "rate", BANDWIDTH_LIMIT, "burst", BANDWIDTH_BURST], 
                             check=True)
                subprocess.run(["tc", "filter", "add", "dev", iface, "protocol", "ip", 
                               "parent", "1:", "prio", "1", "u32", "match", "ip", "dst", ip, 
                               "flowid", "1:1"], check=True)
                self.logger.info(f"Throttled bandwidth for IP: {ip} (MAC: {mac})")
            self.blocked_macs.add(mac)
            self.log_block_event(mac, reason, True)
            self.logger.info(f"Blocked MAC: {mac} (Reason: {reason})")
            subprocess.run(["nft", "list", "ruleset"], stdout=open("/etc/nftables.conf", "w"), check=True)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block MAC {mac}: {e.stderr.decode()}")
            return False

    def unblock_mac(self, mac: str, ip: str = None, reason: str = "Reconnected") -> bool:
        try:
            mac = mac.lower()
            if not self.traffic_monitor.validate_mac(mac):
                self.logger.error(f"Invalid MAC address: {mac}")
                return False
            subprocess.run([
                "nft", "delete", "element", "inet", "mac_filter", "blocked_macs",
                f"{{ {mac} }}"
            ], check=True, stderr=subprocess.PIPE)
            if ip and self.traffic_monitor.validate_ip(ip):
                iface = self.traffic_monitor.interface
                subprocess.run(["tc", "filter", "del", "dev", iface, "protocol", "ip", 
                               "prio", "1", "u32", "match", "ip", "dst", ip], 
                             stderr=subprocess.DEVNULL, check=False)
                subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], 
                             stderr=subprocess.DEVNULL, check=False)
                self.logger.info(f"Removed bandwidth throttle for IP: {ip} (MAC: {mac})")
            self.blocked_macs.discard(mac)
            self.log_block_event(mac, reason, False)
            self.logger.info(f"Unblocked MAC: {mac} (Reason: {reason})")
            subprocess.run(["nft", "list", "ruleset"], stdout=open("/etc/nftables.conf", "w"), check=True)
            return True
        except subprocess.CalledProcessError as e:
            if "No such file or directory" not in e.stderr.decode():
                self.logger.error(f"Failed to unblock MAC {mac}: {e.stderr.decode()}")
            return False

    def log_block_event(self, mac: str, reason: str, is_blocked: bool):
        conn = get_db_connection()
        if not conn:
            return
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO block_log (mac_address, action, reason, timestamp)
                VALUES (%s, %s, %s, NOW())
                """,
                (mac.lower(), "block" if is_blocked else "unblock", reason)
            )
            conn.commit()
        except mysql.connector.Error as e:
            self.logger.error(f"Failed to log block event for {mac}: {e}")
        finally:
            cursor.close()
            conn.close()

    def collect_traffic_periodically(self):
        while running:
            try:
                self.traffic_monitor.collect_traffic_stats()
                time.sleep(SCAN_INTERVAL / 2)  # Collect every 0.5 seconds
            except Exception as e:
                self.logger.error(f"Traffic collection thread error: {e}")
                time.sleep(SCAN_INTERVAL / 2)

    def update_blocked_devices(self, current_macs: Set[str]):
        conn = get_db_connection()
        if not conn:
            return
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT mac_address, ip_address, status, is_permanent FROM active_users_log")
            db_devices = {row['mac_address'].lower(): {'status': row['status'], 'ip': row['ip_address'], 'is_permanent': row['is_permanent']} 
                         for row in cursor.fetchall()}
            
            # Batch updates
            updates = []
            deletes = []
            absent_macs = db_devices.keys() - current_macs
            if absent_macs:
                network = get_network_details()
                confirmation_scan = scan_network(network)
                confirmed_macs = {mac.lower() for _, mac, _ in confirmation_scan}
                absent_macs = absent_macs - confirmed_macs
            
            for mac in db_devices:
                ip = db_devices[mac]['ip']
                status = db_devices[mac]['status']
                is_permanent = db_devices[mac]['is_permanent']
                if mac in absent_macs and not is_permanent:
                    deletes.append((mac,))
                    with data_lock:
                        traffic_data.pop(mac, None)
                        self.traffic_monitor.last_counter_values.pop(mac, None)
                        self.traffic_monitor.packet_counts.pop(mac, None)
                    self.logger.info(f"Deleted MAC {mac} from database (not in scan)")
                    if mac not in self.blocked_macs and status != 'disconnected':
                        self.block_mac(mac, ip, "Device disconnected")
                elif status == 'disconnected' and mac not in self.blocked_macs:
                    self.block_mac(mac, ip, "Device disconnected")
                    if not is_permanent:
                        updates.append((1, mac))
                elif status == 'connected' and mac in self.blocked_macs:
                    self.unblock_mac(mac, ip, "Device reconnected")
                    if is_permanent:
                        updates.append((0, mac))
            
            # Execute batch updates
            if deletes:
                cursor.executemany("DELETE FROM active_users_log WHERE mac_address = %s AND is_permanent = 0", deletes)
            if updates:
                cursor.executemany("UPDATE active_users_log SET is_permanent = %s WHERE mac_address = %s", updates)
            
            conn.commit()
            self.logger.info(f"Processed {len(db_devices)} devices, deleted {len(deletes)}, updated {len(updates)}")
        except mysql.connector.Error as e:
            self.logger.error(f"Database error updating blocked devices: {e}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def monitor_network_status(self):
        global current_subnet
        last_status = True
        while running:
            try:
                iface, _ = get_interface_details()
                new_subnet = get_network_details()
                is_up = bool(netifaces.gateways().get("default", {}).get(netifaces.AF_INET))
                
                if not is_up and last_status:
                    self.logger.warning("Network interface down, clearing active devices")
                    self.clear_active_devices()
                    last_status = False
                elif is_up and not last_status:
                    self.logger.info("Network interface restored")
                    last_status = True
                
                if is_up and current_subnet and new_subnet != current_subnet:
                    self.logger.warning(f"Network swap detected: {current_subnet} -> {new_subnet}")
                    self.clear_active_devices()
                    with data_lock:
                        traffic_data.clear()
                        self.traffic_monitor.last_counter_values.clear()
                        self.traffic_monitor.packet_counts.clear()
                current_subnet = new_subnet
                
                time.sleep(SCAN_INTERVAL)
            except Exception as e:
                self.logger.error(f"Network status monitor error: {e}")
                time.sleep(SCAN_INTERVAL)

    def clear_active_devices(self):
        conn = get_db_connection()
        if not conn:
            return
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM active_users_log WHERE is_permanent = 0")
            count = cursor.rowcount
            conn.commit()
            self.logger.info(f"Cleared {count} non-permanent devices from database")
            self.blocked_macs.clear()
            with data_lock:
                traffic_data.clear()
                self.traffic_monitor.last_counter_values.clear()
                self.traffic_monitor.packet_counts.clear()
            subprocess.run(["nft", "flush", "set", "inet", "mac_filter", "blocked_macs"], 
                         stderr=subprocess.DEVNULL, check=True)
            subprocess.run(["tc", "qdisc", "del", "dev", self.traffic_monitor.interface, "root"], 
                         stderr=subprocess.DEVNULL, check=False)
            subprocess.run(["nft", "list", "ruleset"], stdout=open("/etc/nftables.conf", "w"), check=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to flush nftables: {e.stderr.decode()}")
        except mysql.connector.Error as e:
            self.logger.error(f"Error clearing devices: {e}")
        finally:
            cursor.close()
            conn.close()

def get_db_connection():
    for _ in range(3):
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            conn.autocommit = False
            return conn
        except mysql.connector.Error as e:
            logging.getLogger('NetworkEnforcer').warning(f"Database connection failed: {e}")
            time.sleep(0.1)  # Reduced retry delay
    logging.getLogger('NetworkEnforcer').error("Failed to connect to database after retries")
    return None

def update_database_usage(enforcer: 'NetworkEnforcer'):
    conn = get_db_connection()
    if not conn:
        return
    try:
        cursor = conn.cursor()
        updates = []
        with data_lock:
            for mac in set(traffic_data.keys()) | set(enforcer.traffic_monitor.packet_counts.keys()):
                in_bytes = max(traffic_data.get(mac, {}).get('in_bytes', 0), 
                              enforcer.traffic_monitor.packet_counts.get(mac, {}).get('in_bytes', 0))
                out_bytes = max(traffic_data.get(mac, {}).get('out_bytes', 0), 
                               enforcer.traffic_monitor.packet_counts.get(mac, {}).get('out_bytes', 0))
                in_pkts = max(traffic_data.get(mac, {}).get('in_pkts', 0), 
                             enforcer.traffic_monitor.packet_counts.get(mac, {}).get('in_pkts', 0))
                out_pkts = max(traffic_data.get(mac, {}).get('out_pkts', 0), 
                              enforcer.traffic_monitor.packet_counts.get(mac, {}).get('out_pkts', 0))
                if in_bytes > 0 or out_bytes > 0 or in_pkts > 0 or out_pkts > 0:
                    in_mb = in_bytes / (1024 * 1024)
                    out_mb = out_bytes / (1024 * 1024)
                    total_mb = in_mb + out_mb
                    updates.append((in_mb, out_mb, total_mb, in_pkts, out_pkts, mac.lower()))
                    traffic_data[mac] = {'in_bytes': 0, 'out_bytes': 0, 'in_pkts': 0, 'out_pkts': 0}
                    enforcer.traffic_monitor.packet_counts[mac] = {'in_bytes': 0, 'out_bytes': 0, 'in_pkts': 0, 'out_pkts': 0}
        if updates:
            cursor.executemany(
                """
                UPDATE active_users_log 
                SET data_in_mb = data_in_mb + %s,
                    data_out_mb = data_out_mb + %s,
                    data_usage_mb = data_usage_mb + %s,
                    packets_in = packets_in + %s,
                    packets_out = packets_out + %s,
                    last_seen = NOW()
                WHERE mac_address = %s
                """,
                updates
            )
        conn.commit()
        logging.getLogger('NetworkEnforcer').info(f"Updated {len(updates)} devices in database")
    except mysql.connector.Error as e:
        logging.getLogger('NetworkEnforcer').error(f"Database update failed: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def save_to_db(devices: List[Tuple[str, str, str, str]]) -> None:
    logger = logging.getLogger('NetworkEnforcer')
    conn = get_db_connection()
    if not conn:
        logger.error("Failed to get database connection")
        return
    try:
        cursor = conn.cursor(dictionary=True)
        updates = []
        inserts = []
        existing_macs = set()
        cursor.execute("SELECT mac_address, status FROM active_users_log")
        existing_devices = {row['mac_address'].lower(): row['status'] for row in cursor.fetchall()}
        
        for ip, mac, hostname, status in devices:
            mac = mac.lower()
            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                logger.warning(f"Invalid MAC {mac}, skipping")
                continue
            is_permanent = 1 if status == 'disconnected' else 0
            if mac in existing_devices:
                updates.append((ip, hostname, status, is_permanent, mac))
            else:
                inserts.append((ip, mac, hostname, status, is_permanent))
            existing_macs.add(mac)
        
        if updates:
            cursor.executemany(
                """
                UPDATE active_users_log 
                SET ip_address = %s,
                    hostname = COALESCE(NULLIF(%s, 'Unknown'), hostname),
                    last_seen = NOW(),
                    connection_count = connection_count + 1,
                    status = %s,
                    is_permanent = %s
                WHERE mac_address = %s
                """,
                updates
            )
        if inserts:
            cursor.executemany(
                """
                INSERT INTO active_users_log 
                (ip_address, mac_address, hostname, timestamp, 
                 status, connection_count, is_permanent,
                 data_in_mb, data_out_mb, data_usage_mb,
                 packets_in, packets_out)
                VALUES (%s, %s, %s, NOW(), %s, 1, %s, 0, 0, 0, 0, 0)
                """,
                inserts
            )
        conn.commit()
        logger.debug(f"Updated {len(updates)} devices, inserted {len(inserts)} devices")
    except mysql.connector.Error as e:
        logger.error(f"Database save failed: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def get_device_status(mac_address: str) -> Optional[str]:
    conn = get_db_connection()
    if not conn:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT status FROM active_users_log WHERE mac_address = %s", (mac_address.lower(),))
        result = cursor.fetchone()
        return result['status'] if result else None
    except mysql.connector.Error as e:
        logging.getLogger('NetworkEnforcer').error(f"Failed to retrieve status for MAC {mac_address}: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def signal_all_user():
    conn = get_db_connection()
    if not conn:
        return
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_users_log WHERE is_permanent = 0")
        count = cursor.rowcount
        conn.commit()
        logging.getLogger('NetworkEnforcer').info(f"Deleted {count} non-permanent devices")
    except mysql.connector.Error as e:
        logging.getLogger('NetworkEnforcer').error(f"Error deleting users: {e}")
    finally:
        cursor.close()
        conn.close()

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"

@lru_cache(maxsize=1)
def get_interface_details():
    try:
        gateway_info = netifaces.gateways().get("default", {}).get(netifaces.AF_INET, [None])[1]
        if not gateway_info:
            raise ValueError("No default network interface found")
        iface = gateway_info
        iface_mac = netifaces.ifaddresses(iface).get(netifaces.AF_LINK, [{}])[0].get('addr')
        if not iface_mac:
            raise ValueError(f"Could not get MAC address for interface {iface}")
        logging.getLogger('NetworkEnforcer').debug(f"Interface: {iface}, MAC: {iface_mac}")
        return iface, iface_mac
    except Exception as e:
        logging.getLogger('NetworkEnforcer').error(f"Interface detection failed: {e}")
        return "wlan0", None

def scan_network(network):
    try:
        iface, iface_mac = get_interface_details()
        if not iface or not iface_mac:
            raise ValueError("Invalid interface or MAC")
        arp = ARP(pdst=network)
        ether = Ether(src=iface_mac, dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        devices = []
        for attempt in range(2):  # Reduced retries from 3 to 2
            try:
                responses, _ = srp(
                    packet,
                    timeout=0.5,  # Reduced from 1 second
                    iface=iface,
                    verbose=False,
                    inter=0.05,
                    multi=True,
                    retry=1  # Reduced from 2
                )
                devices = [(resp.psrc, resp.hwsrc.lower(), resolve_hostname(resp.psrc)) 
                          for _, resp in responses if resp.psrc != "0.0.0.0"]
                if devices:
                    break
                time.sleep(0.1)  # Reduced retry delay
            except Exception as e:
                if attempt == 1:
                    logging.getLogger('NetworkEnforcer').warning(f"Network scan failed after retries: {e}")
                    return []
        logging.getLogger('NetworkEnforcer').debug(f"Scanned devices: {len(devices)}")
        return devices
    except Exception as e:
        logging.getLogger('NetworkEnforcer').error(f"Network scan failed: {e}")
        return []

def get_network_details():
    try:
        gateway_info = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
        if not gateway_info:
            raise ValueError("No default gateway found")
        iface = gateway_info[1]
        iface_data = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0]
        ip_address = iface_data.get("addr")
        netmask = iface_data.get("netmask")
        if not ip_address or not netmask:
            raise ValueError("Invalid interface data")
        cidr = sum(bin(int(x)).count("1") for x in netmask.split("."))
        network = f"{ip_address}/{cidr}"
        logging.getLogger('NetworkEnforcer').debug(f"Detected network: {network}")
        return network
    except Exception as e:
        logging.getLogger('NetworkEnforcer').error(f"Subnet detection failed: {e}")
        return "192.168.1.0/24"

def check_pid_file():
    pid = str(os.getpid())
    if os.path.exists(PID_FILE):
        with open(PID_FILE, 'r') as f:
            old_pid = f.read().strip()
        if os.path.exists(f"/proc/{old_pid}"):
            logging.getLogger('NetworkEnforcer').error(f"Another instance is running (PID: {old_pid})")
            sys.exit(1)
    with open(PID_FILE, 'w') as f:
        f.write(pid)
    logging.getLogger('NetworkEnforcer').info(f"Created PID file with PID: {pid}")

def cleanup():
    global running
    if not running:
        return
    running = False
    logging.getLogger('NetworkEnforcer').info("Initiating cleanup")
    signal_all_user()
    try:
        iface, _ = get_interface_details()
        subprocess.run(["nft", "flush", "table", "inet", "mac_filter"], 
                      stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        subprocess.run(["nft", "flush", "table", "inet", "traffic_accounting"], 
                      stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], 
                      stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["nft", "list", "ruleset"], stdout=open("/etc/nftables.conf", "w"), check=True)
    except subprocess.CalledProcessError as e:
        logging.getLogger('NetworkEnforcer').warning(f"Cleanup failed (likely tables absent): {e.stderr.decode()}")
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
        logging.getLogger('NetworkEnforcer').info("Removed PID file")

def signal_handler(signum, frame):
    logging.getLogger('NetworkEnforcer').info(f"Received signal {signum}, initiating shutdown")
    cleanup()
    threading.Timer(3.0, lambda: os._exit(1)).start()

def real_time_network_tracker():
    global current_subnet
    enforcer = NetworkEnforcer()
    current_subnet = get_network_details()
    print("Starting MAC-based Network Security Monitor...")
    print("Press Ctrl+C to stop")
    try:
        subprocess.run(["nft", "list", "table", "inet", "traffic_accounting"], 
                      stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        enforcer.traffic_monitor.ensure_accounting_setup()
    while running:
        try:
            enforcer.logger.info("--- Starting monitoring cycle ---")
            scanned_devices = scan_network(current_subnet)
            current_macs = {mac.lower() for _, mac, _ in scanned_devices}
            with data_lock:
                for mac in list(traffic_data.keys()):
                    if mac not in current_macs:
                        del traffic_data[mac]
                        enforcer.traffic_monitor.last_counter_values.pop(mac, None)
                        enforcer.traffic_monitor.packet_counts.pop(mac, None)
            enforcer.traffic_monitor.update_device_rules(scanned_devices)
            devices_to_save = []
            for ip, mac, hostname in scanned_devices:
                if enforcer.traffic_monitor.validate_ip(ip) and enforcer.traffic_monitor.validate_mac(mac):
                    current_status = get_device_status(mac)
                    status = 'connected' if current_status is None else current_status
                    devices_to_save.append((ip, mac, hostname, status))
            if devices_to_save:
                save_to_db(devices_to_save)
            enforcer.update_blocked_devices(current_macs)
            update_database_usage(enforcer)
            enforcer.logger.info("--- End of monitoring cycle ---")
            time.sleep(SCAN_INTERVAL)
        except Exception as e:
            enforcer.logger.error(f"Monitoring cycle error: {e}")
            time.sleep(SCAN_INTERVAL)

def run():
    logging.basicConfig(level=logging.DEBUG)
    check_pid_file()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        real_time_network_tracker()
    except Exception as e:
        logging.getLogger('NetworkEnforcer').error(f"Fatal error: {e}")
        cleanup()
        sys.exit(1)

if __name__ == "__main__":
    run()