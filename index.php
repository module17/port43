<?php
require_once('inc/config.inc.php');
require_once('inc/autoload.php');
require_once('lib/Cache_Lite/Lite.php');
require_once('classes/Port43.php');

$app = new Port43();
$app->initApp();
?>
<!DOCTYPE html>
<html>
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
        <form id="whois" method="get" action="<?= $_SERVER['PHP_SELF']; ?>" novalidate>
            <p>Enter any <span class="uln">domain</span> name or <strong>IP</strong> address</p>
            <input name="query" class="query" value="<?= ($app->clean_query != '') ? $app->clean_query : ''; ?>"
                   type="url" autofocus>
            &nbsp;<input type="submit" value="Whois &raquo;">
        </form>
    </div>
    <?=$app->outputBody();?>
</div>
<div id="footer">
    <a href="http://www.module17.com" class="module17" rel="external" title="Module 17 | Web development Toronto">Module
        17</a>
</div>
</body>
</html>