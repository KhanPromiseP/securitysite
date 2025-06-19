<?php

class SimpleMiddleware {
    public static function requireLogin() {
        session_start();
        if (!isset($_SESSION['user_id'])) {
            header('Location: views/login.php');
           
        }
    }

    public static function requireAdmin() {
        session_start();
        if (!isset($_SESSION['user_id']) || $_SESSION['role_id'] !== '1') {
            header('Location: access_denied.php');
            exit();
        }
    }

    public static function preventLoggedInAccess() {
        session_start();
        if (isset($_SESSION['user_id'])) {
            header('Location: ../index.php');
            exit();
        }
    }

    public static function logout() {
       
        session_start();
        session_unset();
        session_destroy();
        header('Location: views/login.php');
        exit();
    }
}
