<?php
/* PHP 5.2+ configuration. Keep private; never publish configured copies. */
$diagnostic_secret = 'REPLACE_WITH_A_UNIQUE_RANDOM_PASSWORD';

/* Automatically detect the server's public URL (PHP 5.2+). */
$diagnostic_https  = ((isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off' && $_SERVER['HTTPS'] !== '') || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443));
$diagnostic_scheme = $diagnostic_https ? 'https' : 'http';
$diagnostic_host   = isset($_SERVER['SERVER_NAME']) ? strtolower(trim($_SERVER['SERVER_NAME'])) : '';

/* Validate the hostname before using it in cURL. */
if ($diagnostic_host === '' || strlen($diagnostic_host) > 253 || !preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/D', $diagnostic_host) || strpos($diagnostic_host, '..') !== false) {
	die('ERROR: Unable to determine a valid server hostname.');
}

$diagnostic_base_url = $diagnostic_scheme . '://' . $diagnostic_host;

/* Set true only when you have restricted access by IP or HTTP authentication too. */
$diagnostic_enabled = true;
