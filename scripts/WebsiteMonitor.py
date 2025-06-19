import re
import time
import pymysql
from http.server import BaseHTTPRequestHandler, HTTPServer

# Database Configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",  # Update with your database password
    "database": "securityapp"  # Ensure this matches your MySQL database name
}

# Function to connect to the database
def get_db_connection():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)

# Function to check if an IP is already blocked
def is_ip_blocked(ip):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT is_blocked FROM website_logs WHERE ip_address = %s", (ip,))
            result = cursor.fetchone()
    return result and result["is_blocked"] == 1

# Function to log threats
def log_threat(ip, status, issue):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO website_logs (ip_address, status, issue, checked_at, is_blocked)
                VALUES (%s, %s, %s, NOW(), %s)
                """, (ip, status, issue, 0)
            )
        conn.commit()

# Function to block an IP
def block_ip(ip):
    if not is_ip_blocked(ip):
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE website_logs SET is_blocked = 1, checked_at = NOW() WHERE ip_address = %s
                """, (ip,))
            conn.commit()
        print(f"Blocked IP: {ip}")

# Function to detect SQL Injection
def detect_sql_injection(query):
    sql_patterns = [r"(UNION.*SELECT)", r"(--|#|/\*)", r"(SELECT.*FROM)", r"(INSERT INTO.*VALUES)"]
    return any(re.search(pattern, query, re.IGNORECASE) for pattern in sql_patterns)

# Function to detect XSS
def detect_xss(payload):
    xss_patterns = [r"(<script.*?>.*?</script>)", r"(onerror=|onload=|onclick=)"]
    return any(re.search(pattern, payload, re.IGNORECASE) for pattern in xss_patterns)

# Function to detect DDoS (limit: 100 requests/minute)
def detect_ddos(ip, limit=100):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) AS count FROM website_logs 
                WHERE ip_address = %s AND checked_at >= NOW() - INTERVAL 1 MINUTE
            """, (ip,))
            request_count = cursor.fetchone()["count"]
    return request_count > limit

# Function to detect brute force attacks (5 failed attempts in 1 min)
def detect_brute_force(ip, limit=5):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) AS count FROM website_logs 
                WHERE ip_address = %s AND status = 401 AND checked_at >= NOW() - INTERVAL 1 MINUTE
            """, (ip,))
            failed_attempts = cursor.fetchone()["count"]
    return failed_attempts >= limit

# HTTP Server Handler
class SecurityHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ip = self.client_address[0]

        if is_ip_blocked(ip):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access Denied: Your IP is blacklisted")
            return

        if detect_ddos(ip):
            log_threat(ip, 403, "DDoS Attempt")
            block_ip(ip)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access Denied: DDoS Attempt Detected")
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request Allowed")

    def do_POST(self):
        ip = self.client_address[0]
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode()

        if is_ip_blocked(ip):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access Denied: Your IP is blacklisted")
            return

        if detect_sql_injection(post_data):
            log_threat(ip, 403, "SQL Injection Attempt")
            block_ip(ip)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access Denied: SQL Injection Detected")
            return

        if detect_xss(post_data):
            log_threat(ip, 403, "XSS Attack Attempt")
            block_ip(ip)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access Denied: XSS Attack Detected")
            return

        if detect_brute_force(ip):
            log_threat(ip, 403, "Brute Force Attack")
            block_ip(ip)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access Denied: Too Many Failed Login Attempts")
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request Processed")

# Run the server
def run():
    server_address = ("", 8080)
    httpd = HTTPServer(server_address, SecurityHandler)
    print("Security Monitoring Server Running on Port 8080...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
