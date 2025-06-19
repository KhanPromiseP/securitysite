<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Dotenv\Dotenv;

class Database {
    private $conn;

    public function __construct() {
        $dotenv = Dotenv::createImmutable(__DIR__ . '/../../');
        $dotenv->load();
    }

    public function getConnection() {
        $this->conn = null;
        try {
            // Retrieve values from $_ENV
            $db_name = $_ENV['DB_NAME'];
            $username = $_ENV['DB_USER'];
            $password = $_ENV['DB_PASS'];

            // Force TCP/IP by using 127.0.0.1 and explicit port
            $host = '127.0.0.1'; // Use IP address instead of 'localhost'
            $port = 3306; // Default MySQL port for XAMPP

            $this->conn = new PDO("mysql:host=$host;port=$port;dbname=$db_name", $username, $password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->conn->exec("set names utf8");

        } catch (PDOException $exception) {
            echo "Connection error: " . $exception->getMessage();
        }
        return $this->conn;
    }
}