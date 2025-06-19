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
