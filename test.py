from flask import Flask, request, jsonify
import requests
import logging
from logging.handlers import RotatingFileHandler
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

app = Flask(__name__)

# Logging setup
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler('user_activity.log', maxBytes=5 * 1024 * 1024, backupCount=5)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Email setup
SMTP_SERVER = "smtp.gmail.com"  # Update this
SMTP_PORT = 587
EMAIL_ADDRESS = "your-email@gmail.com"  # Update this
EMAIL_PASSWORD = "your-password"  # Update this
ALERT_RECIPIENT = "alert-recipient@gmail.com"  # Update this

# Monitoring URL
monitoring_url = "http://localhost/securitysite/"  # Replace with actual website URL

# Threat detection functions
def detect_sql_injection(data):
    sql_patterns = [
        r"(\bSELECT\b|\bUNION\b|\bINSERT\b|\bDELETE\b|\bDROP\b|\bUPDATE\b)",
        r"(\b--\b|\bOR\b|\bAND\b\s+['\"])"
    ]
    for pattern in sql_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False

def detect_xss(data):
    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:.*",
        r"<img.*?onerror=.*?>"
    ]
    for pattern in xss_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False

def send_email_alert(ip, threat_type, details):
    try:
        subject = f"Security Alert: {threat_type} Detected"
        body = f"""
        A potential {threat_type} has been detected.

        Details:
        - IP Address: {ip}
        - Description: {details}
        - Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

        Please investigate this issue immediately.
        """
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = ALERT_RECIPIENT
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info(f"Alert email sent: {threat_type} from IP {ip}")
    except Exception as e:
        logger.error(f"Failed to send alert email: {str(e)}")

@app.before_request
def log_request():
    ip = request.remote_addr
    user_data = request.form.to_dict() if request.method == "POST" else request.args.to_dict()
    url = request.url  # Capture the URL that the user visited
    method = request.method  # Capture the HTTP method used (GET, POST, etc.)

    # Log the request details (IP, URL, method, form data)
    logger.info(f"Request from IP {ip} - Method: {method} - URL: {url} - Data: {user_data}")

    # Detect threats (SQL Injection and XSS)
    for key, value in user_data.items():
        if detect_sql_injection(value):
            logger.warning(f"SQL Injection detected from IP {ip} on {url}")
            send_email_alert(ip, "SQL Injection", value)
        if detect_xss(value):
            logger.warning(f"XSS detected from IP {ip} on {url}")
            send_email_alert(ip, "XSS Attack", value)

@app.route("/monitor", methods=["GET", "POST"])
def monitor():
    ip = request.remote_addr
    logger.info(f"Monitoring request from IP {ip} to URL: {monitoring_url}")

    try:
        if request.method == "GET":
            response = requests.get(monitoring_url, params=request.args)
        elif request.method == "POST":
            response = requests.post(monitoring_url, data=request.form)
        else:
            return jsonify({"error": "Unsupported HTTP method"}), 405
        return (response.content, response.status_code, response.headers.items())
    except Exception as e:
        logger.error(f"Error accessing {monitoring_url}: {str(e)}")
        return jsonify({"error": f"Unable to connect to {monitoring_url}"}), 500

if __name__ == "__main__":
    app.run(debug=False, port=5000)
