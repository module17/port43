<?php

/*
 * configuration file
 *
 **/

define('ENV', 'prod'); // [ prod | dev ]

if (ENV == 'dev') {
    define('SITE_ROOT_PATH', '/r1.00/');
} else {
    define('SITE_ROOT_PATH', '/');
}

define('SITE_TITLE', 'port43.net | whois');

define('DB_HOST', 'localhost');
define('DB_USER', '');
define('DB_PASS', '');
define('DB_NAME', 'port43');