<?php
class SimpleMiddleware
{
    /**
     *  Check if the user is logged in
     */
    public static function requireLogin()
    {
        session_start(); 
        if (!isset($_SESSION['user_id'])) {
            header('Location: ../src/config/login.php');
            exit(); 
        }
    }

    /**
     *  Method to prevent logged-in users from accessing public login, register pages
     *  
     */
    public static function preventLoggedInAccess()
    {
        session_start();
        if (isset($_SESSION['user_id'])) {
            header('Location: ../../public/index.php');
            exit(); 
        }
    }

    public static function logout()
    {
        session_start(); 
        session_destroy(); 
        header('Location: src/config/login.php'); 
        exit();
    }
}