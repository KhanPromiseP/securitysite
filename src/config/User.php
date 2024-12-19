<?php
class User {
    private $conn;
    private $table = 'users';

    public $id;
    public $username;
    public $email;
    public $password_hash;
    public $role_id;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function register($username, $email, $password, $role_id = 2) { 
        $query = "INSERT INTO $this->table (username, email, password_hash, role_id) VALUES (:username, :email, :password_hash, :role_id)";
        $stmt = $this->conn->prepare($query);

        $this->username = htmlspecialchars(strip_tags($username));
        $this->email = htmlspecialchars(strip_tags($email));
        $this->password_hash = password_hash($password, PASSWORD_DEFAULT);

        $stmt->bindParam(':username', $this->username);
        $stmt->bindParam(':email', $this->email);
        $stmt->bindParam(':password_hash', $this->password_hash);
        $stmt->bindParam(':role_id', $role_id);

        return $stmt->execute();
    }

    public function login($username, $password) {
        $query = "SELECT id, password_hash, role_id FROM $this->table WHERE username = :username LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && password_verify($password, $user['password_hash'])) {
            session_start();
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role_id'] = $user['role_id'];
            $_SESSION['username']= $username;
            return true;
        }
        return false;
    }

    public function logout() {
        session_start();
        session_unset();
        session_destroy();
        return true;
    }

    public function getAllUsers() {
        $query = "SELECT users.id, users.username, users.email, users.password_hash, roles.role_name 
                  FROM $this->table
                  JOIN roles ON users.role_id = roles.id";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function deleteUser($id) {
        $query = "DELETE FROM $this->table WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':id', $id);
        return $stmt->execute();
    }
    
    public function updateUser($id, $username, $email, $password, $role) {
        if (!empty($password)) {
            // Hash password if provided
            $password = password_hash($password, PASSWORD_DEFAULT);
        } else {
            // If no new password is entered, keep the existing password hash
            $password = $this->getUserPassword($id); // Retrieve the existing password hash
        }
    
        $query = "UPDATE users SET username = :username, email = :email, password = :password, role_id = :role_id WHERE id = :id";
        $stmt = $this->db->prepare($query);
    
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':role_id', $role);
        $stmt->bindParam(':id', $id);
    
        if ($stmt->execute()) {
            return true;
        }
    
        return false;
    }
    
    public function getUserPassword($id) {
        $query = "SELECT password FROM users WHERE id = :id";
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(':id', $id);
        $stmt->execute();

        if (!$stmt->execute()) {
            echo "Error: " . implode(", ", $stmt->errorInfo());
        }

        
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['password'];
    }
    
}
?>
