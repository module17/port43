<?php

// main database functions
class db_func
{
    var $ip_addr_country;

    public function insertStat($query, $cache_id = '', $req_type = 'WHOIS', $referrer = '')
    {
        $short_url = mysql_escape_string($query);
        $visitor_ip = mysql_escape_string($_SERVER['REMOTE_ADDR']);
        $hostname = mysql_escape_string(gethostbyaddr($visitor_ip));
        $user_agent = mysql_escape_string($_SERVER['HTTP_USER_AGENT']);
        $referer = mysql_escape_string($referrer);
        $char = mysql_escape_string($_SERVER['HTTP_ACCEPT_CHARSET']);
        $lang = mysql_escape_string($_SERVER['HTTP_ACCEPT_LANGUAGE']);
        $date = date('Y-m-d');
        $visitor_country = $this->getCountryByIP($visitor_ip);

        // get visitors country based on ip address
        //$ip_addr_country = $this->getCountryByIP($visitor_ip);
        // record the detailed visit to stats table
        $sql = sprintf('INSERT INTO whois_request_log (id,
                                                      timestamp,
                                                      date,
                                                      remote_ip,
                                                      remote_hostname,
                                                      remote_useragent,
                                                      remote_referer,
                                                      remote_charset,
                                                      remote_language,
                                                      query,
                                                      cache_id,
                                                      visitor_country,
                                                      request_type) VALUES (NULL,NOW(),"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s")',
            $date, $visitor_ip, $hostname, $user_agent, $referer, $char, $lang, $query, base64_encode($cache_id), $visitor_country, $req_type);

        $result = DB::query($sql);

        if (DB::error()) {
            die(DB::error());
        }
    }

    public function getCountryByIP($ip)
    {
        $sql = sprintf('SELECT * FROM ip_group_country where ip_start <= INET_ATON("%s") ORDER BY ip_start DESC LIMIT 1', $ip);
        $result = DB::get_row($sql);

        if (DB::error()) {
            die(DB::error());
        }

        $ip_addr_country = $result->country_code;

        if ($ip_addr_country != '') {
            $this->ip_addr_country = $ip_addr_country;
        } else {
            $this->ip_addr_country = '';
        }

        return $this->ip_addr_country;
    }

    function getTLD($domain)
    {
        $extracted_tld = $domain;
        $sql = sprintf('SELECT url_page_title FROM tld_support_list WHERE tld = "%s"', $extracted_tld);
        $result = DB::get_row($sql);

        // error handling should be nicer
        if (DB::error()) {
            die(DB::error());
        }

        $short_title = $result->url_page_title;
        $this->short_title = $short_title;
        return true;
    }

}