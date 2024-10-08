from scapy.all import sniff, IP, TCP
import mysql.connector
import time

def log_packet_data_to_db(ip_src, ip_dst, protocol):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="security_app"
    )
    cursor = conn.cursor()

    cursor.execute("SELECT is_blocked FROM suspicious_behavior WHERE ip_address = %s AND is_blocked = 1", (ip_src,))
    if cursor.fetchone():
        print(f"Blocked IP {ip_src} tried to communicate. Ignoring...")
        cursor.close()
        conn.close()
        return

    query = "INSERT INTO network_activity (ip_source, ip_dest, protocol, timestamp) VALUES (%s, %s, %s, %s)"
    values = (ip_src, ip_dst, protocol, time.strftime('%Y-%m-%d %H:%M:%S'))
    cursor.execute(query, values)
    conn.commit()
    cursor.close()
    conn.close()

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet.sprintf("%IP.proto%")
        log_packet_data_to_db(ip_src, ip_dst, protocol)

sniff(prn=packet_callback, store=0)
