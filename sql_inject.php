<?php

$response = array(
    'ok' => -1,
    'msg' => '',
    'result' => array()
);

$title = $_POST['title'];
$author = $_POST['author'];
if ((!isset($title) && !isset($author))
    || ($title === "" && $author === "")
) {
    $response['msg'] = 'Please give at least one param for searching!';
    echo json_encode($response);
    exit;
}

require "con_database.php";

$query = mysqli_query($con, "select title,author from books where title like '%$title%' and author like '%$author%'") or die('SQL Query Failed'.mysqli_error($con));

$response['ok'] = 1;
while ($row = $query->fetch_assoc()) {
    $response['result'][] = $row;
}
echo json_encode($response);

mysqli_close($con);
