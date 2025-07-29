<?php 

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
        header('Location: ./login.php');
        
    }

include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';
include __DIR__ . '/../../includes/navbar.php';


include '../../src/config/middleware.php';
SimpleMiddleware::requireAdmin();

?>