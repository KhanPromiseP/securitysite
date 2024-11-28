
CREATE DATABASE security_app;

use security_app;

CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE
);

INSERT INTO roles (role_name) VALUES ('Admin'), ('User');

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL
);

CREATE TABLE active_users_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active_user_count INT NOT NULL
);


CREATE TABLE IF NOT EXISTS generated_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(255) NOT NULL,
    report_details TEXT NOT NULL,
    generated_at DATETIME NOT NULL,
    entry_id INT NOT NULL,
    CONSTRAINT fk_network_logs_entry FOREIGN KEY (entry_id)
        REFERENCES network_logs (id)
        ON DELETE CASCADE,
    CONSTRAINT fk_website_logs_entry FOREIGN KEY (entry_id)
        REFERENCES website_logs (id)
        ON DELETE CASCADE
);



CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(255) NOT NULL,
    block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    status ENUM('UP', 'DOWN', 'SUSPICIOUS') NOT NULL,
    response_time DECIMAL(10, 3),
    issue TEXT,
    ip_address VARCHAR(45),
    is_blocked BOOLEAN DEFAULT 1,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
