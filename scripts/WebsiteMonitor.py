import asyncio
import aiohttp
import logging
import json
import ssl
import time
import datetime
from collections import defaultdict
import aiomysql

# Setup Logging
logging.basicConfig(
    filename="../logs/user_activity_monitor.json",
    filemode="a",
    level=logging.DEBUG,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}',
)

# Database Configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "db": "security_app",
}

# Global Variables
SUSPICIOUS_IPS = set()
WHITELISTED_IPS = {"127.0.0.1"}
BLOCKED_IPS = set()
RATE_LIMIT_THRESHOLD = 100
RATE_LIMIT_WINDOW = 60
USER_SESSIONS = defaultdict(list)

# Rate Limit Tracking
RATE_LIMIT = defaultdict(lambda: {"timestamp": time.time(), "count": 0})

# Suspicious Patterns
SQL_KEYWORDS = ["UNION", "SELECT", "DROP", "INSERT", "--", "#"]
XSS_PAYLOADS = ["<script>", "</script>", "onerror=", "onload="]
MALICIOUS_PATTERNS = SQL_KEYWORDS + XSS_PAYLOADS

# Max failed login attempts before blocking
MAX_FAILED_ATTEMPTS = 5
FAILED_ATTEMPT_WINDOW = 300  # 5 minutes


def get_user_ip(headers, response):
    """Extract the user's IP address."""
    return headers.get("X-Forwarded-For") or response.url.host


def is_rate_limited(ip):
    """Check if an IP exceeds the rate limit."""
    current_time = time.time()
    window = RATE_LIMIT[ip]

    if current_time - window["timestamp"] > RATE_LIMIT_WINDOW:
        window["timestamp"] = current_time
        window["count"] = 0

    window["count"] += 1
    return window["count"] > RATE_LIMIT_THRESHOLD


async def block_ip(ip, reason):
    """Block an IP address unless whitelisted."""
    if ip in WHITELISTED_IPS:
        logging.info(json.dumps({"action": "whitelist", "ip": ip}))
        return

    if ip not in BLOCKED_IPS:
        BLOCKED_IPS.add(ip)
        logging.warning(json.dumps({"action": "block", "ip": ip, "reason": reason}))
    else:
        logging.info(json.dumps({"action": "already_blocked", "ip": ip}))


async def log_event(conn, log_data):
    """Log user activity to the database."""
    query = """
    INSERT INTO user_activity_logs (action, ip_address, user_agent, session_id, is_blocked, timestamp)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    try:
        async with conn.cursor() as cursor:
            await cursor.execute(query, log_data)
            await conn.commit()
    except aiomysql.MySQLError as err:
        logging.error(json.dumps({"action": "db_error", "error": str(err)}))


async def detect_threat(ip, body, headers, session_id):
    """Detect suspicious activity."""
    for pattern in MALICIOUS_PATTERNS:
        if pattern.lower() in body.lower() or pattern.lower() in str(headers).lower():
            logging.warning(json.dumps({"action": "threat_detected", "ip": ip, "pattern": pattern}))
            SUSPICIOUS_IPS.add(ip)
            await block_ip(ip, "Malicious pattern detected")
            return f"Threat detected: {pattern}"

    if is_rate_limited(ip):
        logging.warning(json.dumps({"action": "rate_limit_exceeded", "ip": ip}))
        SUSPICIOUS_IPS.add(ip)
        await block_ip(ip, "Rate limit exceeded")
        return "Rate limit exceeded"

    return None


async def handle_login_attempt(ip, user_id, success=False):
    """Handle login attempts and block IP after multiple failed attempts."""
    current_time = time.time()
    USER_SESSIONS[ip].append({"user_id": user_id, "time": current_time, "success": success})

    # Keep only recent login attempts within the window
    USER_SESSIONS[ip] = [entry for entry in USER_SESSIONS[ip] if current_time - entry["time"] < FAILED_ATTEMPT_WINDOW]

    failed_attempts = sum(1 for entry in USER_SESSIONS[ip] if not entry["success"])

    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        logging.warning(json.dumps({"action": "block_due_to_failed_login", "ip": ip, "failed_attempts": failed_attempts}))
        await block_ip(ip, "Too many failed login attempts")


async def monitor_user_activity(url, session_id, conn):
    """Monitor user activity."""
    logging.info(json.dumps({"action": "monitor_start", "url": url}))
    timeout = aiohttp.ClientTimeout(total=30)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with aiohttp.ClientSession(timeout=timeout) as session:
        headers = {"User-Agent": "Mozilla/5.0"}
        try:
            start_time = time.time()
            async with session.get(url, headers=headers, ssl=ssl_context) as response:
                body = await response.text()
                ip = get_user_ip(headers, response)
                response_time = time.time() - start_time

                # Monitor login attempts (if applicable, like login.php)
                if "login.php" in url:  # Adjust URL condition as needed
                    user_id = headers.get("User-Agent", "Unknown")  # Replace with actual user identifier if available
                    success = response.status == 200
                    await handle_login_attempt(ip, user_id, success)

                issue = await detect_threat(ip, body, headers, session_id)
                log_data = (
                    "Page Access",
                    ip,
                    headers.get("User-Agent", ""),
                    session_id,
                    ip in BLOCKED_IPS,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
                await log_event(conn, log_data)

                return {
                    "url": url,
                    "status": response.status,
                    "response_time": response_time,
                    "ip_address": ip,
                    "issue": issue,
                }
        except Exception as e:
            logging.error(json.dumps({"error": "request_error", "url": url, "details": str(e)}))
            return {
                "url": url,
                "status": "Failed",
                "response_time": 0,
                "ip_address": "N/A",
                "issue": str(e),
            }


async def monitor_background():
    """Run monitoring tasks in the background."""
    conn = await aiomysql.connect(**DB_CONFIG)
    tasks = [
        monitor_user_activity("http://localhost/personal_website/index.php", "session1", conn),
        # Add more URLs to monitor here
    ]
    results = await asyncio.gather(*tasks)

    for result in results:
        logging.info(json.dumps({"action": "monitor_result", "result": result}))


async def main():
    """Main entry point."""
    await monitor_background()


if __name__ == "__main__":
    asyncio.run(main())
