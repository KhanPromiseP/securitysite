CREATE DATABASE securityapp;
use securityapp;
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE
);
INSERT INTO roles (role_name)
VALUES ('Admin'),
    ('User');
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE
    SET NULL
);
CREATE TABLE active_users_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(15) NOT NULL,
    mac_address VARCHAR(17) NOT NULL,
    hostname VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_ip (ip_address)
);
CREATE TABLE IF NOT EXISTS network_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    threat_type VARCHAR(50),
    user_crime VARCHAR(255),
    is_blocked BOOLEAN DEFAULT 1,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS website_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(255) NOT NULL,
    status INT NOT NULL,
    response_time FLOAT DEFAULT NULL,
    issue TEXT DEFAULT NULL,
    ip_address VARCHAR(45) NOT NULL,
    session_id TEXT DEFAULT NULL,
    is_blocked BOOLEAN DEFAULT FALSE,
    user_agent VARCHAR(255) NOT NULL,
    headers JSON NOT NULL,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(255) NOT NULL,
    block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS generated_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(255) NOT NULL,
    report_details TEXT NOT NULL,
    generated_at DATETIME NOT NULL,
    network_entry_id INT,
    website_entry_id INT,
    CONSTRAINT fk_network_logs_entry FOREIGN KEY (network_entry_id) REFERENCES network_logs (id) ON DELETE CASCADE,
    CONSTRAINT fk_website_logs_entry FOREIGN KEY (website_entry_id) REFERENCES website_logs (id) ON DELETE CASCADE
);


-- Persistent user history table
CREATE TABLE user_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL,
    ip_address VARCHAR(15),
    hostname VARCHAR(255),
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    total_data_mb FLOAT DEFAULT 0,
    current_week_data_mb FLOAT DEFAULT 0,
    data_limit_mb FLOAT DEFAULT 0,       -- Added for data limits
    is_active BOOLEAN DEFAULT FALSE,
    is_throttled BOOLEAN DEFAULT FALSE,  -- Added for throttling status
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX (mac_address),
    INDEX (is_active),
    INDEX (is_throttled)
);

CREATE TABLE user_limits_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL,
    data_limit_mb FLOAT NOT NULL,
    action VARCHAR(50) NOT NULL COMMENT 'SET_LIMIT,REMOVE_LIMIT,THROTTLE,UNTHROTTLE',
    performed_by VARCHAR(255) NOT NULL,
    performed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX (mac_address),
    INDEX (performed_at)
);

CREATE TABLE network_limit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL COMMENT 'Device MAC address',
    action VARCHAR(50) NOT NULL COMMENT 'Action type: SET_LIMIT, REMOVE_LIMIT, THROTTLE, UNTHROTTLE',
    old_value FLOAT DEFAULT NULL COMMENT 'Previous limit value (in MB)',
    new_value FLOAT DEFAULT NULL COMMENT 'New limit value (in MB)',
    performed_by VARCHAR(255) DEFAULT NULL COMMENT 'User/admin who performed action',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'When action occurred',
    notes TEXT DEFAULT NULL COMMENT 'Additional context or reason',
    
    INDEX idx_mac (mac_address),
    INDEX idx_action (action),
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Logs of network limit changes';



-- Weekly reset log
CREATE TABLE weekly_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    reset_time DATETIME NOT NULL,
    users_affected INT NOT NULL
);





-- somechanges
ALTER TABLE network_logs
  ADD COLUMN src_port INT,
  ADD COLUMN dst_port INT,
  ADD COLUMN protocol VARCHAR(10),
  ADD COLUMN event_type VARCHAR(20),
  ADD COLUMN signature VARCHAR(255),
  ADD COLUMN severity VARCHAR(10),
  ADD COLUMN src_country VARCHAR(2),
  ADD COLUMN dst_country VARCHAR(2);

CREATE TABLE suricata_alerts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  timestamp DATETIME,
  src_ip VARCHAR(45),
  src_port INT,
  dst_ip VARCHAR(45),
  dst_port INT,
  protocol VARCHAR(10),
  signature VARCHAR(255),
  severity VARCHAR(10),
  raw_event JSON
);

CREATE TABLE network_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    threat_type VARCHAR(100),
    user_crime VARCHAR(255),
    is_blocked BOOLEAN,
    detected_at DATETIME,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(10),
    event_type VARCHAR(50),
    signature TEXT,
    severity VARCHAR(10),
    src_country VARCHAR(5),
    dst_country VARCHAR(5)
);
