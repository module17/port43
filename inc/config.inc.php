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