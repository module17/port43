<?php
function __autoload($class) {
    $class = str_replace('\\', DIRECTORY_SEPARATOR, $class);
    $file = __DIR__ . "/../lib/" . $class . '.php';
    if (file_exists($file)) {
        require $file;
    }
}