<?php
class SimpleMiddleware {
    public static function requireLogin() {
        session_start();
        if (!isset($_SESSION['user_id'])) {
            header('Location: ../src/config/login.php');
            exit();
        }
    }

    public static function requireAdmin() {
        session_start();
        if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
            header('Location: ../views/access_denied.php');
            exit();
        }
    }

    public static function preventLoggedInAccess() {
        session_start();
        if (isset($_SESSION['user_id'])) {
            header('Location: ../public/index.php');
            exit();
        }
    }

    public static function logout() {
        session_start();
        session_unset();
        session_destroy();
        header('Location: src/config/login.php');
        exit();
    }
}
