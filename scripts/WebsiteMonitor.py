#!/usr/bin/env python3
import re
import sys
import time
import random
import argparse
import logging
import requests
import pymysql
import dns.resolver
import socket
import ssl
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('security_scan.log', maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('AdvancedSecurityScanner')

class AdvancedSecurityScanner:
    def __init__(self, target_url):
        """Initialize the scanner with enhanced validation and configuration"""
        # Security configuration with optimized defaults
        self.config = {
            'timeout': 20,  # Increased timeout for reliability
            'max_redirects': 5,
            'throttle_delay': (1.0, 3.0),  # More conservative delays
            'user_agents': [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                "SecurityScanner/3.0 (Compatible; Research)"
            ],
            'security_headers': {
                'Content-Security-Policy': {
                    'severity': 'high',
                    'description': 'Prevents XSS, clickjacking, and other code injection attacks',
                    'validate': lambda x: bool(x.strip())
                },
                'Strict-Transport-Security': {
                    'severity': 'high',
                    'description': 'Enforces HTTPS connections (min 1 year with includeSubDomains)',
                    'validate': lambda x: 'max-age=' in x.lower() and 
                                        int(re.search(r'max-age=(\d+)', x.lower()).group(1)) >= 31536000 and
                                        'includesubdomains' in x.lower()
                },
                'X-Frame-Options': {
                    'severity': 'medium',
                    'description': 'Should be set to DENY or SAMEORIGIN',
                    'validate': lambda x: x.lower() in ['deny', 'sameorigin']
                },
                'X-Content-Type-Options': {
                    'severity': 'medium',
                    'description': 'Should be set to nosniff',
                    'validate': lambda x: x.lower() == 'nosniff'
                },
                'Referrer-Policy': {
                    'severity': 'low',
                    'description': 'Should be set to strict-origin-when-cross-origin or stricter',
                    'validate': lambda x: x.lower() in [
                        'no-referrer', 
                        'no-referrer-when-downgrade',
                        'strict-origin',
                        'strict-origin-when-cross-origin'
                    ]
                },
                'Permissions-Policy': {
                    'severity': 'medium',
                    'description': 'Should restrict sensitive features like geolocation, camera',
                    'validate': lambda x: bool(x.strip())
                }
            },
            'sensitive_paths': {
                "admin/": {"severity": "high", "type": "Admin Interface"},
                "wp-admin/": {"severity": "critical", "type": "WordPress Admin"},
                "phpmyadmin/": {"severity": "critical", "type": "phpMyAdmin"},
                ".git/": {"severity": "critical", "type": "Git Repository"},
                ".env": {"severity": "critical", "type": "Environment File"},
                "config.php": {"severity": "high", "type": "Configuration File"},
                "backup/": {"severity": "high", "type": "Backup Directory"},
                "debug/": {"severity": "high", "type": "Debug Endpoint"},
                "api/docs/": {"severity": "medium", "type": "API Documentation"},
                "swagger-ui/": {"severity": "medium", "type": "Swagger UI"},
                "graphql/": {"severity": "medium", "type": "GraphQL Endpoint"}
            },
            'trusted_domains': ['github.com', 'google.com', 'microsoft.com']  # Domains with known good security
        }

        # Initialize scanner state
        self.target_url = self.normalize_url(target_url)
        self.parsed_url = urlparse(self.target_url)
        self.domain = self.parsed_url.netloc
        self.vulnerabilities = []
        self.db_connected = False
        self.session = self.create_session()
        self.start_time = datetime.now()
        self.scan_id = None

    def normalize_url(self, url):
        """Ensure URL is properly formatted with validation"""
        url = (url or '').strip().rstrip('/')
        if not url:
            raise ValueError("URL cannot be empty")
            
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'  # Default to HTTPS
            
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValueError("Invalid domain in URL")
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")

    def create_session(self):
        """Create a requests session with enhanced security settings"""
        session = requests.Session()
        session.headers.update({
            "User-Agent": random.choice(self.config['user_agents']),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1"  # Do Not Track header
        })
        session.max_redirects = self.config['max_redirects']
        
        # Configure retry strategy
        retry_strategy = requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=10,
            pool_maxsize=10
        )
        session.mount("https://", retry_strategy)
        session.mount("http://", retry_strategy)
        
        return session

    def throttle(self):
        """Add intelligent delay between requests"""
        delay = random.uniform(*self.config['throttle_delay'])
        
        # Increase delay for certain domains to avoid rate limiting
        if any(domain in self.domain for domain in ['github.com', 'gitlab.com']):
            delay *= 2
            
        time.sleep(delay)

    def connect_db(self):
        """Connect to database with enhanced error handling and retries"""
        DB_CONFIG = {
            "host": "localhost",
            "user": "security_scanner",
            "password": "ComplexPassword123!",
            "database": "security_scans",
            "connect_timeout": 10,
            "ssl": {"ca": "/path/to/ca-cert.pem"}  # Enable SSL for database connection
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.conn = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
                
                with self.conn.cursor() as cursor:
                    # Create tables with proper constraints if they don't exist
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS scan_results (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            scan_id VARCHAR(36) NOT NULL,
                            url VARCHAR(512) NOT NULL,
                            vulnerability_type VARCHAR(100) NOT NULL,
                            severity ENUM('critical', 'high', 'medium', 'low', 'info') NOT NULL,
                            details TEXT,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            INDEX(url),
                            INDEX(severity),
                            INDEX(scan_id)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """)
                    
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS scan_metadata (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            scan_id VARCHAR(36) NOT NULL,
                            url VARCHAR(512) NOT NULL,
                            start_time DATETIME NOT NULL,
                            end_time DATETIME,
                            vulnerabilities_found INT,
                            status ENUM('running', 'completed', 'failed') NOT NULL,
                            INDEX(url),
                            UNIQUE(scan_id)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """)
                
                self.conn.commit()
                self.db_connected = True
                logger.info("Database connection established")
                return
                
            except pymysql.Error as e:
                logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    logger.error("Max database connection attempts reached")
                    self.db_connected = False
                time.sleep(2 ** attempt)  # Exponential backoff

    def log_vulnerability(self, vulnerability_type, severity, details=""):
        """Enhanced vulnerability logging with context awareness"""
        # Skip known false positives for trusted domains
        if any(domain in self.domain for domain in self.config['trusted_domains']):
            if vulnerability_type in [
                "DNSSEC Not Implemented",
                "Missing SPF Record",
                "Missing DKIM Record"
            ]:
                logger.debug(f"Skipping known non-issue for {self.domain}: {vulnerability_type}")
                return

        entry = {
            "type": vulnerability_type,
            "severity": severity,
            "details": details,
            "url": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "scan_id": self.scan_id
        }
        self.vulnerabilities.append(entry)
        
        # Enhanced logging format
        log_msg = f"[{severity.upper()}] {vulnerability_type}"
        if details:
            log_msg += f" | {details[:200]}{'...' if len(details) > 200 else ''}"
        
        # Color coding by severity
        if severity == 'critical':
            log_msg = f"\033[91m{log_msg}\033[0m"  # Red
        elif severity == 'high':
            log_msg = f"\033[93m{log_msg}\033[0m"  # Yellow
        
        logger.warning(log_msg)

        if self.db_connected:
            try:
                with self.conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, url, vulnerability_type, severity, details)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (self.scan_id, self.target_url, vulnerability_type, severity, details))
                self.conn.commit()
            except Exception as e:
                logger.error(f"Failed to log vulnerability to DB: {e}")

    def check_dns_security(self):
        """Comprehensive DNS security checks with enhanced validation"""
        if any(domain in self.domain for domain in self.config['trusted_domains']):
            logger.info(f"Skipping DNS checks for trusted domain: {self.domain}")
            return

        try:
            # DNSSEC validation
            try:
                answers = dns.resolver.resolve(self.domain, 'DNSKEY', raise_on_no_answer=False)
                if not answers.rrset:
                    self.log_vulnerability(
                        "DNSSEC Not Implemented", 
                        "medium",
                        "DNSSEC provides DNS data integrity through cryptographic signing"
                    )
                else:
                    # Verify DNSSEC is properly configured
                    try:
                        dns.resolver.resolve(self.domain, 'A', raise_on_no_answer=False)
                    except dns.resolver.NXDOMAIN:
                        self.log_vulnerability(
                            "DNSSEC Misconfigured",
                            "high",
                            "DNSSEC appears implemented but causes resolution failures"
                        )
            except Exception as e:
                logger.warning(f"DNSSEC check failed: {e}")

            # Email security records with enhanced checks
            email_checks = {
                '_dmarc': {
                    'record': 'DMARC',
                    'description': 'Prevents email spoofing and phishing',
                    'min_requirements': 'p=reject or p=quarantine with sp=reject'
                },
                '_spf': {
                    'record': 'SPF',
                    'description': 'Prevents sender address forgery',
                    'min_requirements': '~all or -all at end of record'
                },
                'default._domainkey': {
                    'record': 'DKIM',
                    'description': 'Provides email authentication through cryptographic signing',
                    'min_requirements': 'v=DKIM1; k=rsa;'
                }
            }

            for prefix, config in email_checks.items():
                try:
                    answers = dns.resolver.resolve(f"{prefix}.{self.domain}", 'TXT', raise_on_no_answer=False)
                    if not answers.rrset:
                        self.log_vulnerability(
                            f"Missing {config['record']} Record", 
                            "medium",
                            config['description']
                        )
                    else:
                        # Validate record content
                        records = [r.to_text() for r in answers.rrset]
                        if config['record'] == 'SPF' and not any('all' in r.lower() for r in records):
                            self.log_vulnerability(
                                f"Weak {config['record']} Record",
                                "medium",
                                f"SPF record should end with ~all or -all: {records}"
                            )
                except Exception as e:
                    logger.warning(f"{config['record']} check failed: {e}")

        except Exception as e:
            logger.error(f"DNS security check failed: {e}")

    def check_ssl_tls(self):
        """Comprehensive SSL/TLS check with protocol and cipher suite validation"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((self.domain, 443), timeout=self.config['timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Certificate validation
                    self.validate_certificate(cert)
                    
                    # Protocol validation
                    self.validate_protocol(protocol)
                    
                    # Cipher suite validation
                    self.validate_cipher(cipher)
                    
        except Exception as e:
            logger.error(f"SSL/TLS check failed: {e}")
            self.log_vulnerability(
                "SSL/TLS Verification Failed",
                "high",
                f"Could not establish secure connection: {str(e)}"
            )

    def validate_certificate(self, cert):
        """Validate certificate properties"""
        if not cert:
            self.log_vulnerability(
                "Missing SSL Certificate",
                "critical",
                "No certificate presented by server"
            )
            return
            
        # Check expiration
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_remaining = (not_after - datetime.now()).days
        
        if days_remaining < 0:
            self.log_vulnerability(
                "Expired SSL Certificate",
                "critical",
                f"Certificate expired on {not_after.date()}"
            )
        elif days_remaining < 30:
            self.log_vulnerability(
                "SSL Certificate Expiring Soon",
                "high",
                f"Certificate expires on {not_after.date()} ({days_remaining} days remaining)"
            )
            
        # Check subjectAltName
        san_entries = []
        for field in cert.get('subjectAltName', []):
            san_entries.append(f"{field[0]}: {field[1]}")
            
        if not san_entries:
            self.log_vulnerability(
                "Missing Subject Alternative Names",
                "medium",
                "Certificate should include subjectAltName entries"
            )
        elif f"DNS:{self.domain}" not in ",".join(san_entries):
            self.log_vulnerability(
                "Certificate Name Mismatch",
                "high",
                f"Certificate does not cover {self.domain}. SANs: {', '.join(san_entries)}"
            )

    def validate_protocol(self, protocol):
        """Validate TLS protocol version"""
        deprecated_protocols = {
            'SSLv2': 'critical',
            'SSLv3': 'critical',
            'TLSv1': 'high',
            'TLSv1.1': 'medium'
        }
        
        if protocol in deprecated_protocols:
            self.log_vulnerability(
                "Deprecated Protocol Version",
                deprecated_protocols[protocol],
                f"Server uses {protocol} which has known vulnerabilities"
            )
        elif protocol != 'TLSv1.3':
            self.log_vulnerability(
                "Older Protocol Version",
                "low",
                f"Consider upgrading from {protocol} to TLSv1.3 for best security"
            )

    def validate_cipher(self, cipher):
        """Validate cipher suite strength"""
        if not cipher:
            self.log_vulnerability(
                "No Cipher Suite Negotiated",
                "critical",
                "Failed to negotiate a cipher suite with the server"
            )
            return
            
        name, version, bits = cipher
        weak_ciphers = {
            'NULL': 'critical',
            'EXP': 'critical',
            'RC4': 'critical',
            'DES': 'high',
            '3DES': 'medium',
            'CBC': 'medium'
        }
        
        for pattern, severity in weak_ciphers.items():
            if pattern in name.upper():
                self.log_vulnerability(
                    "Weak Cipher Suite",
                    severity,
                    f"Server uses {name} which has known vulnerabilities"
                )
                return
                
        if int(bits) < 128:
            self.log_vulnerability(
                "Weak Encryption Strength",
                "high",
                f"Cipher {name} uses only {bits}-bit encryption"
            )

    def check_security_headers(self):
        """Comprehensive security header analysis with enhanced validation"""
        try:
            self.throttle()
            response = self.session.head(
                self.target_url,
                timeout=self.config['timeout'],
                allow_redirects=True
            )
            headers = {k.lower(): v for k, v in response.headers.items()}  # Case-insensitive
            
            # Check modern security headers
            for header, config in self.config['security_headers'].items():
                header_lower = header.lower()
                if header_lower not in headers:
                    self.log_vulnerability(
                        f"Missing Security Header: {header}",
                        config['severity'],
                        config['description']
                    )
                elif not config['validate'](headers[header_lower]):
                    self.log_vulnerability(
                        f"Misconfigured Security Header: {header}",
                        config['severity'],
                        f"Current value: {headers[header_lower]}. Recommended: {config['description']}"
                    )
            
            # Check for server information leaks
            for info_header in ['server', 'x-powered-by', 'x-aspnet-version']:
                if info_header in headers:
                    self.log_vulnerability(
                        "Server Information Disclosure",
                        "low",
                        f"{info_header} header reveals: {headers[info_header]}"
                    )
                    
        except requests.RequestException as e:
            logger.error(f"Error checking security headers: {e}")

    def scan_for_injections(self):
        """Comprehensive injection testing with enhanced detection"""
        try:
            self.throttle()
            response = self.session.get(
                self.target_url,
                timeout=self.config['timeout']
            )
            soup = BeautifulSoup(response.text, 'html.parser')

            # Test forms for SQLi and XSS
            forms = soup.find_all('form')
            if not forms:
                logger.info("No forms found for testing")
                return

            for form in forms:
                form_details = self.get_form_details(form)
                if not form_details['action']:
                    continue

                # Test SQLi with more sophisticated payloads
                self.test_sqli(form_details)
                
                # Test XSS with context-aware payloads
                self.test_xss(form_details)
                
                # Test for CSRF vulnerability
                self.test_csrf(form_details)

        except Exception as e:
            logger.error(f"Injection scan failed: {e}")

    def get_form_details(self, form):
        """Extract form details with enhanced parsing and validation"""
        action = form.get('action', '').strip()
        details = {
            'action': self.make_absolute_url(action) if action else self.target_url,
            'method': form.get('method', 'get').lower(),
            'inputs': [],
            'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
            'csrf_protected': False
        }

        # Find all input fields
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.get('type', 'text').lower()
            input_name = input_tag.get('name', '')
            input_value = input_tag.get('value', '')
            
            # Skip inputs without names
            if not input_name:
                continue
                
            # Check for CSRF tokens
            if any(token in input_name.lower() for token in ['csrf', '_token', 'authenticity_token']):
                details['csrf_protected'] = True
                
            details['inputs'].append({
                'type': input_type,
                'name': input_name,
                'value': input_value,
                'tag': input_tag.name
            })

        return details

    def test_sqli(self, form_details):
        """Test for SQL injection with time-based and boolean-based techniques"""
        # Context-aware payloads based on form type
        payload_sets = {
            'auth': [
                "' OR '1'='1'-- ",
                "admin'-- ",
                '" OR ""="'
            ],
            'search': [
                "1 AND 1=1",
                "1 AND SLEEP(5)",
                "1 UNION SELECT null,table_name,null FROM information_schema.tables--"
            ],
            'generic': [
                "1; SELECT pg_sleep(5)--",
                "1 UNION SELECT null,version(),null--",
                "1 OR EXISTS(SELECT * FROM information_schema.tables)--"
            ]
        }

        # Determine payload set based on form context
        form_context = 'generic'
        if 'login' in form_details['action'] or 'auth' in form_details['action']:
            form_context = 'auth'
        elif 'search' in form_details['action'] or 'q=' in form_details['action']:
            form_context = 'search'
            
        payloads = payload_sets[form_context]

        for payload in payloads:
            form_data = {}
            for field in form_details['inputs']:
                if field['type'] in ['text', 'password', 'search', 'email', 'textarea']:
                    form_data[field['name']] = payload
                else:
                    form_data[field['name']] = field['value']

            try:
                start_time = time.time()
                if form_details['method'] == 'post':
                    response = self.session.post(
                        form_details['action'],
                        data=form_data,
                        timeout=self.config['timeout'],
                        allow_redirects=False
                    )
                else:
                    response = self.session.get(
                        form_details['action'],
                        params=form_data,
                        timeout=self.config['timeout'],
                        allow_redirects=False
                    )
                response_time = time.time() - start_time

                # Check for SQL error patterns
                error_indicators = [
                    'sql syntax',
                    'mysql.*error',
                    'warning.*mysql',
                    'unclosed quotation',
                    'syntax error',
                    'postgres.*error',
                    'oracle.*error',
                    'odbc.*error',
                    'sqlite.*error',
                    'syntax error'
                ]

                content = response.text.lower()
                if any(re.search(pattern, content) for pattern in error_indicators):
                    self.log_vulnerability(
                        "SQL Injection Vulnerability",
                        "critical",
                        f"Detected in form at {form_details['action']} with payload: {payload}"
                    )
                    break  # No need to test other payloads if one works

                # Check for time-based SQLi
                if response_time > 5:  # Significant delay
                    self.log_vulnerability(
                        "Potential Time-Based SQL Injection",
                        "high",
                        f"Response delay ({response_time:.2f}s) with payload: {payload}"
                    )

                # Check for boolean-based differences
                if "error" not in content.lower() and "invalid" not in content.lower():
                    control_response = self.get_control_response(form_details)
                    if response.text != control_response.text:
                        self.log_vulnerability(
                            "Potential Blind SQL Injection",
                            "high",
                            f"Different response with payload: {payload}"
                        )

            except requests.RequestException as e:
                logger.error(f"Error testing form at {form_details['action']}: {e}")

    def get_control_response(self, form_details):
        """Get a control response for comparison in blind SQLi tests"""
        form_data = {}
        for field in form_details['inputs']:
            form_data[field['name']] = field['value'] or "1"  # Default safe value
            
        if form_details['method'] == 'post':
            return self.session.post(
                form_details['action'],
                data=form_data,
                timeout=self.config['timeout'],
                allow_redirects=False
            )
        else:
            return self.session.get(
                form_details['action'],
                params=form_data,
                timeout=self.config['timeout'],
                allow_redirects=False
            )

    def test_xss(self, form_details):
        """Test for XSS with context-aware payloads and encoding detection"""
        payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            
            # Encoded variations
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            
            # DOM-based XSS
            "\" onfocus=\"alert('XSS')\" autofocus=\"",
            "' onmouseover='alert(\"XSS\")'",
            
            # JavaScript URIs
            "javascript:alert('XSS')",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
        ]

        for payload in payloads:
            form_data = {}
            for field in form_details['inputs']:
                if field['type'] in ['text', 'textarea', 'search', 'email', 'url']:
                    form_data[field['name']] = payload
                else:
                    form_data[field['name']] = field['value']

            try:
                if form_details['method'] == 'post':
                    response = self.session.post(
                        form_details['action'],
                        data=form_data,
                        timeout=self.config['timeout'],
                        allow_redirects=False
                    )
                else:
                    response = self.session.get(
                        form_details['action'],
                        params=form_data,
                        timeout=self.config['timeout'],
                        allow_redirects=False
                    )

                # Check if payload appears in response
                if payload in response.text:
                    self.log_vulnerability(
                        "Reflected XSS Vulnerability",
                        "high",
                        f"Detected in form at {form_details['action']} with payload: {payload}"
                    )
                    break

                # Check for encoded versions
                if any(enc in response.text for enc in [
                    payload.replace('<', '&lt;').replace('>', '&gt;'),
                    payload.replace('"', '&quot;'),
                    payload.replace("'", '&#39;'),
                    payload.replace('/', '&#x2F;')
                ]):
                    self.log_vulnerability(
                        "Potential XSS Vulnerability",
                        "medium",
                        f"Input reflection detected in form at {form_details['action']}"
                    )

            except requests.RequestException as e:
                logger.error(f"Error testing form at {form_details['action']}: {e}")

    def test_csrf(self, form_details):
        """Check for CSRF protection"""
        if not form_details['csrf_protected']:
            self.log_vulnerability(
                "Missing CSRF Protection",
                "high",
                f"Form at {form_details['action']} appears to lack CSRF token"
            )

    def scan_sensitive_paths(self):
        """Check for sensitive files with content analysis and backup pattern detection"""
        sensitive_paths = self.config['sensitive_paths']
        
        # Add common backup file patterns
        backup_patterns = [
            '~', '.bak', '.old', '.orig', '.temp',
            '_backup', '-backup', '.swp', '.swo'
        ]
        
        # Check both directories and files with backup patterns
        for path, info in sensitive_paths.items():
            # Check directory
            self.check_sensitive_path(path, info)
            
            # Check common backup extensions
            if '.' in path:  # It's a file path
                for ext in backup_patterns:
                    backup_path = f"{path}{ext}"
                    self.check_sensitive_path(backup_path, {
                        'severity': 'high',
                        'type': f"Backup of {info['type']}"
                    })

    def check_sensitive_path(self, path, info):
        """Check a single sensitive path with enhanced validation"""
        test_url = f"{self.target_url}/{path}"
        try:
            self.throttle()
            response = self.session.get(
                test_url,
                timeout=5,
                allow_redirects=False
            )

            # Skip if redirected to a different domain or login page
            location = response.headers.get('location', '')
            if response.status_code in [301, 302] and urlparse(location).netloc != self.domain:
                return

            # Check for generic error pages
            error_indicators = [
                "404", "not found", "error", "page not found",
                "does not exist", "access denied", "forbidden"
            ]
            page_text = response.text.lower()
            is_error_page = any(indicator in page_text for indicator in error_indicators)

            if response.status_code == 200 and not is_error_page:
                # Additional validation for certain file types
                if path.endswith('.env'):
                    if any(
                        term in page_text 
                        for term in ['database', 'password', 'secret', 'api_key']
                    ):
                        self.log_vulnerability(
                            f"Exposed {info['type']}",
                            "critical",
                            f"Contains sensitive credentials: {test_url}"
                        )
                elif path.endswith('.git/'):
                    if any(
                        term in page_text 
                        for term in ['repository', 'git', 'refs', 'objects']
                    ):
                        self.log_vulnerability(
                            f"Exposed {info['type']}",
                            "critical",
                            f"Git repository accessible at: {test_url}"
                        )
                else:
                    self.log_vulnerability(
                        f"Exposed {info['type']}",
                        info['severity'],
                        f"Accessible at: {test_url}"
                    )

        except requests.RequestException:
            pass

    def run_scan(self):
        """Execute comprehensive security scan with proper resource management"""
        try:
            # Generate a unique scan ID
            self.scan_id = str(uuid.uuid4())
            
            self.connect_db()
            if self.db_connected:
                with self.conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO scan_metadata 
                        (scan_id, url, start_time, status)
                        VALUES (%s, %s, %s, 'running')
                    """, (self.scan_id, self.target_url, self.start_time))
                self.conn.commit()

            logger.info(f"Starting comprehensive scan of {self.target_url}")
            
            # Perform security checks in optimal order
            checks = [
                self.check_dns_security,
                self.check_ssl_tls,
                self.check_security_headers,
                self.scan_sensitive_paths,
                self.scan_for_injections
            ]
            
            for check in checks:
                try:
                    check()
                except Exception as e:
                    logger.error(f"Check failed: {str(e)}")
                    continue

            logger.info("Scan completed successfully")
            return self.vulnerabilities

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
        finally:
            if self.db_connected:
                try:
                    with self.conn.cursor() as cursor:
                        cursor.execute("""
                            UPDATE scan_metadata 
                            SET end_time = %s,
                                vulnerabilities_found = %s,
                                status = %s
                            WHERE scan_id = %s
                        """, (
                            datetime.now(),
                            len(self.vulnerabilities),
                            'completed' if not sys.exc_info()[0] else 'failed',
                            self.scan_id
                        ))
                    self.conn.commit()
                except Exception as e:
                    logger.error(f"Failed to update scan metadata: {e}")
                
                self.conn.close()

def print_results(vulnerabilities):
    """Display scan results with enhanced formatting and actionable insights"""
    if not vulnerabilities:
        print("\n✅ No critical security vulnerabilities found!")
        print("Note: Some informational findings may still require review")
        return

    # Group by severity and category
    findings = {
        'authentication': [],
        'injection': [],
        'misconfiguration': [],
        'information': []
    }
    
    for vuln in vulnerabilities:
        if 'sql' in vuln['type'].lower() or 'xss' in vuln['type'].lower():
            findings['injection'].append(vuln)
        elif 'missing' in vuln['type'].lower() or 'misconfigured' in vuln['type'].lower():
            findings['misconfiguration'].append(vuln)
        elif 'auth' in vuln['type'].lower() or 'csrf' in vuln['type'].lower():
            findings['authentication'].append(vuln)
        else:
            findings['information'].append(vuln)

    print(f"\n🔍 Security Scan Results ({len(vulnerabilities)} findings)")
    print("=" * 100)
    
    # Print by category
    for category, items in findings.items():
        if not items:
            continue
            
        print(f"\n{category.upper()} ISSUES:")
        print("-" * 50)
        
        for i, vuln in enumerate(items, 1):
            print(f"\n{i}. [{vuln['severity'].upper()}] {vuln['type']}")
            print(f"   URL: {vuln['url']}")
            if vuln['details']:
                print(f"   Details: {vuln['details']}")
            if 'timestamp' in vuln:
                print(f"   Detected: {vuln['timestamp']}")
                
            # Add remediation advice
            print("   Suggested Fix:", end=" ")
            if 'sql' in vuln['type'].lower():
                print("Use parameterized queries/prepared statements")
            elif 'xss' in vuln['type'].lower():
                print("Implement output encoding and Content-Security-Policy")
            elif 'missing' in vuln['type'].lower() and 'header' in vuln['type'].lower():
                print(f"Add {vuln['type'].split(':')[-1].strip()} header to server configuration")
            elif 'csrf' in vuln['type'].lower():
                print("Implement anti-CSRF tokens in all state-changing forms")
            else:
                print("Review and implement appropriate security controls")

    print("\n" + "=" * 100)
    print("\nPriority Recommendations:")
    print("🟥 Critical/High: Address immediately (within 24 hours)")
    print("🟨 Medium: Schedule remediation (within 1 week)")
    print("🟦 Low/Info: Review during next maintenance window")
    print("\nFor detailed remediation guidance, consult OWASP Cheat Sheets:")
    print("https://cheatsheetseries.owasp.org/")

def main():
    """Main execution with enhanced argument handling and validation"""
    parser = argparse.ArgumentParser(
        description='Enterprise Website Security Scanner',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        'url',
        help='URL to scan (e.g., https://example.com)'
    )
    parser.add_argument(
        '--output',
        help='Output file for JSON results',
        default=None
    )