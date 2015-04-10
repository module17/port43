<?php
/*
 * main functions file for port43
 *
 */

// validate a  URL or web address
function is_hostname($domain_name)
{
    $pieces = explode(".", $domain_name);
    if (sizeof($pieces) <= 1) return false;

    foreach ($pieces as $piece) {
        if (!preg_match('/^[a-z\d][a-z\d-]{0,62}$/i', $piece) || preg_match('/-$/', $piece)) {
            return false;
        }
    }
    return true;
}

function is_ipaddress($val)
{
    return (bool)preg_match("/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/",
        $val);
}

// extract only the root domain even if valid sub-domain is supplied
function parse_url_domain($url)
{
    $raw_url = parse_url($url);
    preg_match("/\.([^\/]+)/", $raw_url['host'], $domain_only);
    return $domain_only[1];
}

// a simple function to output text in a centered div
function htmlCenter($html)
{
    return "<div class=\"center\">" . $html . "</div>";
}

function outputResults($data, $query)
{
    $heading = ($query != '') ? htmlCenter("<strong>Results for $query</strong>") . "<br/>" : "";

    $out = <<<DATA
<!--results-->
<div id="response">
$heading
<blockquote>
$data
</blockquote>
</div>
<!--/results-->
DATA;

    return formatOutput(cleanOutput($out));
}

function cleanOutput($out)
{
    // utf-8 perhaps
    $out = utf8_encode($out);

    // replace server IP address with cool name
    $out = str_replace('192.168.0.1', 'port43.net', $out);

    // detect dates and highlight thme
    $out = findDate($out);
    return $out;
}

// when a user pastes a URL with http it causes an error
function stripProtocols($str)
{
    $protocols = array('http', 'ftp');

    // clean trailing slash
    $str = rtrim($str, "/");

    foreach ($protocols as $prot) {
        $suffix = '://';
        $str = str_replace($prot . $suffix, '', $str);
    }
    // also strip common subdomains
    return stripSubdomains($str);
}

// when a user pastes a URL with http it causes an error
function stripSubdomains($str)
{
    $subdomains = array('www', 'ns1', 'ns2', 'ns3', 'news');

    foreach ($subdomains as $prot) {
        $suffix = '.';
        $str = str_replace($prot . $suffix, '', $str);
    }
    // also strip common subdomains
    return $str;
}

function highlightHtml($str)
{
    return '<span class="hilite">' . $str . '</span>';
}

function findDate($str)
{
    $str = preg_replace('/\d{4}\/\d{2}\/\d{2}/', '<span class="hilite">$0</span>', $str);  //1999/02/02
    $str = preg_replace('/\d{1,2}\/\d{1,2}\/\d{4}/', '<span class="hilite">$0</span>', $str);  //01/01/1999
    $str = preg_replace('/\d{4}\-\d{1,2}\-\d{1,2}/', '<span class="hilite">$0</span>', $str);  //1998-04-06
    $str = preg_replace('/\d{1,2}\.\d{1,2}\.\d{4}/', '<span class="hilite">$0</span>', $str);  //3.8.2006
    $str = preg_replace('/\d{4}\.\d{1,2}\.\d{1,2}/', '<span class="hilite">$0</span>', $str);  //2010.07.23
    $str = preg_replace('/\d{1,2}\-[A-Za-z]{3,4}\-\d{4}/', '<span class="hilite">$0</span>', $str);  //01-Jun-1999
    $str = preg_replace('/[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} [A-Za-z]{3} \d{4}/', '<span class="hilite">$0</span>', $str);  //Wed Jul 21 20:08:21 GMT 2010
    $str = preg_replace('/ \d{4}-\d{4} /', '<span class="hilite">$0</span>', $str);  //2007-2009
    $str = preg_replace('/[A-Za-z]{3,4}\, \d{2} [A-Za-z]{3,4} \d{4}/', '<span class="hilite">$0</span>', $str);  //Wed, 06 Apr 2011
    $str = preg_replace('/\d{2}\-[A-Za-z]{3,4}\-\d{2}/', '<span class="hilite">$0</span>', $str);  //30-May-99
    return $str;
}

// TODO: highlight name servers based on standard prefixes
function findNameservers($str)
{
    $nameserver_prefixes = array('ns', 'ns1', 'ns2', 'ns3', 'ns4');
}

// some basic error corrections for user query
function fixQuery($str)
{
    $str = str_replace(',', '.', $str); // a comma typo

    return $str;
}

function formatOutput($out)
{
    // Add bold field names
    $out = preg_replace("/(?m)^([-\s\.&;'\w\t\(\)\/]+:\s*)/", '<strong>$1</strong>', $out);
    // Add italics for disclaimer
    $out = preg_replace("/(?m)^(%.*)/", '<em>$0</em>', $out);
    return $out;
}

function makeLinks($result, $out, $linkself = false)
{
    // adds links fort HTML output
    $email_regex = "/([-_\w\.]+)(@)([-_\w\.]+)\b/i";
    $html_regex = "/(?:^|\b)((((http|https|ftp):\/\/)|(www\.))([\w\.]+)([,:%#&\/?~=\w+\.-]+))(?:\b|$)/is";
    $ip_regex = "/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/i";

    //$out = strip_tags($out);
    $out = preg_replace($email_regex, '<a href="mailto:$0">$0</a>', $out);
    $out = preg_replace_callback($html_regex, 'href_replace', $out);

    if ($linkself) {

        $link = '/?query=';
        $out = preg_replace($ip_regex, '<a href="' . $link . '$0">$0</a>', $out);

        if (isset($result['regrinfo']['domain']['nserver'])) {
            $nserver = $result['regrinfo']['domain']['nserver'];
        } else {
            $nserver = false;
        }

        if (isset($result['regrinfo']['network']['nserver'])) {
            $nserver = $result['regrinfo']['network']['nserver'];
        }

        if (is_array($nserver)) {
            reset($nserver);
            while (list($host, $ip) = each($nserver)) {
                $url = '<a href="' . str_replace('$0', $ip, $link) . "$host\">$host</a>";
                $out = str_replace($host, $url, $out);
                $out = str_replace(strtoupper($host), $url, $out);
            }
        }
    }

    return $out;
}

function detectOutput()
{
    if (!empty($_GET['output'])) {
        $output = $_GET['output'];
        // allowed outputs
        $allow = array('nice', 'object', 'text', 'proxy');
        if (in_array($output, $allow)) {
            $output = $_GET['output'];
        } else {
            $output = '';
        }
    } else {
        $output = '';
    }
    return $output;
}

function generateOutput($output, $whois, $result)
{
    // determine what output was requested and generate it
    switch ($output) {
        case 'object':
            if ($whois->Query['status'] < 0) {
                $winfo = implode($whois->Query['errstr'], "\n<br/><br/>");
            } else {
                $utils = new utils;
                $winfo = $utils->showObject($result);
            }
            break;
        case 'nice':
            if (!empty($result['rawdata'])) {
                $utils = new utils;
                $winfo = $utils->showHTML($result);
            } else {
                if (isset($whois->Query['errstr'])) {
                    $winfo = htmlCenter(implode($whois->Query['errstr'], "\n<br/><br/>"));
                } else {
                    $winfo = htmlCenter('EOF-11');
                }
            }
            break;
        case 'proxy':
            if ($allowproxy) {
                exit(serialize($result));
            }
        default:
            if (!empty($result['rawdata'])) {
                $winfo .= '<pre>' . implode($result['rawdata'], "\n") . '</pre>';
            } else {
                if (is_array($whois->Query['errstr'])) {
                    $winfo = htmlCenter(implode($whois->Query['errstr'], "\n<br/><br/>"));
                } else {
                    $winfo = htmlCenter('EOF-17');
                }
            }
    }
    return $winfo;
}