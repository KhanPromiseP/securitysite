<?php 
include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';



session_start();
include '../../src/config/middleware.php';
SimpleMiddleware::requireAdmin();

?>