
CREATE DATABASE security_app;

use security_app;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_sessions (
    user_id INT PRIMARY KEY,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status ENUM('online', 'offline') DEFAULT 'online'
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

CREATE TABLE suspicious_behavior (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    behavior_details TEXT,
    detection_time DATETIME,
    is_blocked  BOOLEAN DEFAULT 1,
    blocked_at DATETIME,
    unblocked_at DATETIME DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);


CREATE TABLE user_behavior (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    login_time DATETIME,
    failed_logins INT,
    activity JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
