import time
import mysql.connector
import subprocess
import logging
from datetime import datetime
import signal
import sys
import os
import fcntl
from config import running  # Import shared running flag

# Configuration
CONFIG = {
    'db': {
        'host': 'localhost',
        'user': 'root',
        'password': '',
        'database': 'securityapp'
    },
    'network': {
        'interface': 'eth0',
        'throttle_speed': '64kbit',
        'normal_speed': '1024kbit',
        'check_interval': 60,
        'lockfile': '/var/lock/network_limiter.lock'
    },
    'logging': {
        'file': '/opt/lampp/htdocs/securitysite/logs/network_limiter.log',
        'level': logging.INFO
    }
}

# Set up logging
os.makedirs(os.path.dirname(CONFIG['logging']['file']), exist_ok=True)
logging.basicConfig(
    filename=CONFIG['logging']['file'],
    level=CONFIG['logging']['level'],
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger()

class NetworkLimiter:
    def __init__(self):
        self.lockfile = None
        # Remove signal handlers; rely on NetworkScanner.py
        logger.info("NetworkLimiter initialized")

    def acquire_lock(self):
        """Acquire exclusive lock to prevent multiple instances"""
        try:
            self.lockfile = open(CONFIG['network']['lockfile'], 'w')
            fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            logger.info("Acquired exclusive lock")
            return True
        except (IOError, BlockingIOError):
            logger.error("Another instance is already running")
            return False

    def release_lock(self):
        """Release the exclusive lock"""
        if self.lockfile:
            fcntl.flock(self.lockfile, fcntl.LOCK_UN)
            self.lockfile.close()
            try:
                os.unlink(CONFIG['network']['lockfile'])
            except OSError:
                pass
            logger.info("Released lock")

    def db_connect(self):
        """Establish database connection with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                conn = mysql.connector.connect(**CONFIG['db'])
                logger.debug("Database connection established")
                return conn
            except mysql.connector.Error as e:
                logger.warning(f"Database connection failed (attempt {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    logger.error("Max database connection retries reached")
                    return None
                time.sleep(1)  # Reduced sleep for faster shutdown
        return None

    def get_throttled_users(self):
        """Get list of users that need throttling changes"""
        conn = self.db_connect()
        if not conn:
            return []
        try:
            cursor = conn.cursor(dictionary=True)
            query = """
                SELECT mac_address, is_throttled 
                FROM user_history
                WHERE is_active = TRUE
                AND updated_at > DATE_SUB(NOW(), INTERVAL 1 DAY)
            """
            cursor.execute(query)
            users = cursor.fetchall()
            cursor.close()
            return users
        except Exception as e:
            logger.error(f"Error fetching throttled users: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def check_tc_setup(self):
        """Check if TC root qdisc is properly set up"""
        try:
            result = subprocess.run(
                ['sudo', 'tc', 'qdisc', 'show', 'dev', CONFIG['network']['interface']],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2
            )
            return "htb" in result.stdout
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            logger.error(f"Error checking TC setup: {e}")
            return False

    def setup_tc_root(self):
        """Set up the root qdisc if not exists"""
        try:
            subprocess.run([
                'sudo', 'tc', 'qdisc', 'add',
                'dev', CONFIG['network']['interface'],
                'root', 'handle', '1:', 'htb', 'default', '30'
            ], check=True, timeout=5)
            logger.info("Created root HTB qdisc")
            return True
        except subprocess.TimeoutExpired:
            logger.error("Timeout setting up TC root qdisc")
            return False
        except subprocess.CalledProcessError as e:
            if "File exists" in str(e.stderr):
                logger.debug("Root qdisc already exists")
                return True
            logger.error(f"Error setting up TC root: {e.stderr}")
            return False

    def apply_tc_rules(self, mac, throttle):
        """Apply traffic control rules using tc"""
        interface = CONFIG['network']['interface']
        try:
            check_cmd = ['sudo', 'tc', 'filter', 'show', 'dev', interface]
            result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=2)
            rule_exists = mac in result.stdout
            if throttle:
                if not self.check_tc_setup():
                    if not self.setup_tc_root():
                        return False
                if "class htb 1:30" not in result.stdout:
                    subprocess.run([
                        'sudo', 'tc', 'class', 'add', 'dev', interface,
                        'parent', '1:', 'classid', '1:30', 'htb',
                        'rate', CONFIG['network']['throttle_speed']
                    ], check=True, timeout=5)
                if not rule_exists:
                    subprocess.run([
                        'sudo', 'tc', 'filter', 'add', 'dev', interface,
                        'protocol', 'ip', 'parent', '1:', 'prio', '1',
                        'u32', 'match', 'ether', 'dst', mac,
                        'flowid', '1:30'
                    ], check=True, timeout=5)
                    logger.info(f"Throttled {mac} to {CONFIG['network']['throttle_speed']}")
                return True
            elif rule_exists:
                subprocess.run([
                    'sudo', 'tc', 'filter', 'del', 'dev', interface,
                    'protocol', 'ip', 'parent', '1:', 'prio', '1',
                    'u32', 'match', 'ether', 'dst', mac
                ], check=True, timeout=5)
                logger.info(f"Removed throttle for {mac}")
                return True
            return False
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            logger.error(f"TC command failed for {mac}: {e}")
            return False

    def log_action(self, mac, action):
        """Log the action to database"""
        max_retries = 2
        for attempt in range(max_retries):
            conn = self.db_connect()
            if not conn:
                time.sleep(1)
                continue
            try:
                cursor = conn.cursor()
                query = """
                    INSERT INTO network_limit_logs 
                    (mac_address, action, timestamp, performed_by) 
                    VALUES (%s, %s, %s, 'network_limiter')
                """
                cursor.execute(query, (mac, action, datetime.now()))
                conn.commit()
                cursor.close()
                return True
            except Exception as e:
                logger.warning(f"Error logging action (attempt {attempt + 1}): {e}")
            finally:
                if conn:
                    conn.close()
            time.sleep(1)
        return False

    def cleanup_tc(self):
        """Clean up all tc rules on shutdown"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                check_cmd = [
                    'sudo', 'tc', 'qdisc', 'show',
                    'dev', CONFIG['network']['interface']
                ]
                result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=2)
                if result.returncode != 0 or "qdisc noqueue" in result.stdout:
                    logger.info("No TC rules to clean up")
                    return True
                del_cmd = [
                    'sudo', 'tc', 'qdisc', 'del',
                    'dev', CONFIG['network']['interface'], 'root'
                ]
                result = subprocess.run(del_cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    logger.info("Successfully cleaned up TC rules")
                    return True
                if "No such file or directory" in result.stderr:
                    logger.info("No TC rules to clean up (already removed)")
                    return True
                logger.warning(f"TC cleanup attempt {attempt + 1} failed: {result.stderr}")
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                logger.error(f"Error during TC cleanup: {e}")
            time.sleep(1)
        logger.error("Failed to clean up TC rules after multiple attempts")
        return False

    def run(self):
        """Main execution loop"""
        if not self.acquire_lock():
            logger.error("Failed to acquire lock, exiting")
            sys.exit(1)
        logger.info("Starting network limiter service")
        try:
            self.cleanup_tc()
            while running:  # Use shared running flag
                try:
                    users = self.get_throttled_users()
                    for user in users:
                        success = self.apply_tc_rules(
                            user['mac_address'],
                            user['is_throttled']
                        )
                        if success:
                            self.log_action(
                                user['mac_address'],
                                'THROTTLE' if user['is_throttled'] else 'UNTHROTTLE'
                            )
                    time.sleep(1)  # Check running every second
                except Exception as e:
                    logger.error(f"Error in main loop: {str(e)}")
                    time.sleep(1)
        finally:
            self.cleanup_tc()
            self.release_lock()
            logger.info("Network limiter stopped")

if __name__ == "__main__":
    os.makedirs(os.path.dirname(CONFIG['network']['lockfile']), exist_ok=True)
    limiter = NetworkLimiter()
    limiter.run()