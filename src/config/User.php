<?php
class User {
    private $conn;
    private $table = 'users';

    public $id;
    public $username;
    public $email;
    public $password_hash;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function register($username, $email, $password) {
        $query = "INSERT INTO $this->table (username, email, password_hash) VALUES (:username, :email, :password_hash)";

        $stmt = $this->conn->prepare($query);

        $this->username = htmlspecialchars(strip_tags($username));
        $this->email = htmlspecialchars(strip_tags($email));
        $this->password_hash = password_hash($password, PASSWORD_DEFAULT);

        $stmt->bindParam(':username', $this->username);
        $stmt->bindParam(':email', $this->email);
        $stmt->bindParam(':password_hash', $this->password_hash);

        if ($stmt->execute()) {
            return true;
        }
        return false;
    }

    /**
     *  Authenticate user login
     *  @param mixed $username
     * 
     *  @param mixed $password 
     */
    public function login($username, $password):bool {
        $query = "SELECT id, password_hash FROM $this->table WHERE username = :username LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && password_verify($password, $user['password_hash'])) {
          
            session_start();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $username;

            return true;
        }
        return false;
    }

    /**
     * Logout user
    */   
 public function logout():bool {
        session_start();
        session_destroy();
        return true;
    }

    /**
     * Check if a user is logged in 
     *
    */   
    public function isLoggedIn() {
        session_start();
        return isset($_SESSION['user_id']);
    }
}