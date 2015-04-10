<?php

require_once('lib/ezdb/ezdb.class.php');

// database connection info
$dbhost = "localhost";
$dbuser = "changeme";
$dbpass = "changeme";
$dbname = "port43";

// implement ezDB database class and use mysqli
DB::init('mysqli');
DB::connect($dbuser, $dbpass, $dbhost);
DB::select($dbname);