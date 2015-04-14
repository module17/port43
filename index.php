<?php
/*
 *
 * a simple whois interface weekend hack
 *
 **/
session_start();

require_once('inc/config.inc.php');
require_once('inc/db.inc.php');

// require libraries and classes
require_once('classes/Port43.php');
require_once('lib/Cache_Lite-1.7.9/Lite.php');
require_once('lib/whois/whois.main.php');
require_once('lib/whois/whois.utils.php');

$app = new Port43();

// set initial referer session variable to store where user initially came from
if (!isset($_SESSION['referer'])) {
    $_SESSION['referer'] = $_SERVER['HTTP_REFERER'];
}

if (isset($_GET['query'])) {
    // some sanitization should occur here, check for valid domain name or ip address
    $query = $app->stripProtocols($app->fixQuery(trim($_GET['query'])));

    if ($app->is_ipaddress($query) || $app->is_hostname($query)) {
        $output = $app->detectOutput();

        // create whois object
        $whois = new Whois();

        // Set to true if you want to allow proxy requests
        $allowproxy = false;

        // uncomment the following line to get faster but less acurate results
        //$whois->deep_whois = false;
        // To use special whois servers (see README)
        //$whois->UseServer('uk','whois.nic.uk:1043?{hname} {ip} {query}');
        //$whois->UseServer('au','whois-check.ausregistry.net.au');
        // uncomment the following line to add support for non ICANN tld's
        $whois->non_icann = true;

        // Set a id for this cache
        $cache_id = base64_encode($query);
        // Set a few options
        $options = array(
            'cacheDir' => 'tmp/',
            'lifeTime' => 1700
        );
        // Create a Cache_Lite object
        $Cache_Lite = new Cache_Lite($options);

        // Test if there is a valid cache for this id
        if ($data = $Cache_Lite->get($cache_id)) {
            // Cache hit !
            // get cache age, experimental
            //$mod = $Cache_List->lastModified;

            // record the cache hit to the log database table
            $app->insertStat($query, '', 'CACHE', $_SESSION['referer']);

            $mod = '<!--17' . date('Ymdhms') . '-17-->';
            $output_data = $data . "\n" . $mod . "\n";
        } else {
            // process the query further to ensure only top level domain is used
            // prevent usage of subdomains as they have same whois result and return error when supplied
            // No valid cache found so get the whois results
            $result = $whois->Lookup($query);
            // generate nice html or text output
            $output_data = $app->generateOutput($output, $whois, $result);

            // record the hit to the log database table
            $app->insertStat($query, $cache_id, 'WHOIS', $_SESSION['referer']);

            // save the data to cache
            $Cache_Lite->save($output_data);
        }
    } else {
        // send an error
        $error_msg = 'Query terms are ambiguous';

        // record error query to database as well to see what users are doing and make app better
        $app->insertStat($query, '', 'ERROR', $_SESSION['referer']);
    }

    // sanitize query string for usage in input field
    $clean_query = stripslashes($app->fixQuery(trim($_GET['query'])));
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <title><?= SITE_TITLE; ?></title>
    <link href="favicon.ico" rel="shortcut icon" type="image/x-icon"/>
    <link href="css/main.css" rel="stylesheet" type="text/css"/>
</head>

<body>
<div id="board">
    <div id="header">
        <?php
        include_once('inc/logo.ascii.inc.html');
        ?>
    </div>
    <div id="querybox">
        <form id="whois" method="get" action="<?=$_SERVER['PHP_SELF'];?>" novalidate>
            <p>Enter any <span class="uln">domain</span> name or <strong>IP</strong> address
                <br/><br/>
                <input name="query" class="query" value="<?php $o = (isset($_GET['query'])) ? $clean_query : '';
                echo $o; ?>" type="url" autofocus>
                &nbsp;<input type="submit" value="Whois &raquo;">
            </p>
        </form>
    </div>
    <?php
    if (isset($output_data)) {
        // make links
        define('MAKE_LINKS', true);
        if (MAKE_LINKS) {
            $out = $app->outputResults($output_data, $query);
            //$url_params = parse_url($_SERVER['PHP_SELF']);
            echo $app->makeLinks($result, $out, true) . "\n";
        } else {
            $out = $app->outputResults($output_data, $query) . "\n";
            echo $out;
        }
    } elseif (isset($error_msg)) {
        echo "<div class=\"center\">" . $error_msg . "</div>";
    }
    ?>
</div>
<div id="footer">
    <a href="http://www.module17.com" class="module17" rel="external" title="Module 17 | Web development Toronto">Module 17</a>
</div>
</body>
</html>
