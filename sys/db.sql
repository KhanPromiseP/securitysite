CREATE DATABASE IF NOT EXISTS network_monitor;
USE network_monitor;

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
    status ENUM('UP', 'DOWN', 'SUSPICIOUS') NOT NULL,
    response_time DECIMAL(10, 3),
    issue TEXT,
    ip_address VARCHAR(45),
    is_blocked BOOLEAN DEFAULT 1,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
