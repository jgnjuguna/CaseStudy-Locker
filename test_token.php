<?php
$email = "maya@campus.edu";
$day = gmdate("Y-m-d");

echo sha1(strtolower($email) . "|" . $day) . PHP_EOL;
