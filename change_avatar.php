<?php

/* NOTE: `avatars/shell.php` has been disabled for security reasons */
if (!isset($_GET['route'])) {
    echo "<script>location.href='index.php?route=profile.php'</script>";
    exit;
}

include $_GET['route'];
