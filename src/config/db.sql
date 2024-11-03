
CREATE DATABASE security_app;

use security_app;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE active_users_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active_user_count INT NOT NULL
);



CREATE TABLE suspicious_traffic (
    id INT AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(45),
    dest_ip VARCHAR(45),
    packet_size INT,
    protocol VARCHAR(10),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE suspicious_emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender VARCHAR(255),
    recipient VARCHAR(255),
    subject TEXT,
    body TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);




CREATE TABLE suspicious_files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255),
    file_size BIGINT,
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_path TEXT
);


CREATE TABLE IF NOT EXISTS suspicious_behavior (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    ip_address VARCHAR(45),
    behavior_details TEXT,
    detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT 1,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Table to store network activity
CREATE TABLE IF NOT EXISTS network_activity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_source VARCHAR(45),
    ip_dest VARCHAR(45),
    protocol VARCHAR(20),
    data_volume INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE generated_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(255) NOT NULL,
    report_details TEXT NOT NULL,
    generated_at DATETIME NOT NULL
);


CREATE TABLE IF NOT EXISTS user_behavior (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    activity TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(255) NOT NULL,
    block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE detected_vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    vulnerability_type VARCHAR(255),
    details TEXT,
    detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
