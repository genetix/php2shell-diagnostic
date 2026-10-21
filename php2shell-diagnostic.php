<?php
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');

require dirname(__FILE__) . '/php2shell-config.php';

function diag_line($key, $value) { echo str_pad($key, 36) . ': ' . $value . "\n"; }
function diag_equal($a, $b) {
	if (!is_string($a) || !is_string($b) || strlen($a) !== strlen($b)) {
		return false;
	}

	$diff = 0;
	for ($i = 0; $i < strlen($a); $i++) {
		$diff |= ord($a[$i]) ^ ord($b[$i]);
	}

	return $diff === 0;
}
function diag_value($v) { return is_string($v) && trim($v) !== '' ? trim($v) : '—'; }
function diag_cfg($key) {
	$value = ini_get($key);

	if ($value === false) {
		return '(unavailable)';
	}
	if ($value === '') {
		return '(empty)';
	}

	return $value;
}
function diag_public_ipv4($ip) {
	$n = ip2long($ip);
	if ($n === false) {
		return false;
	}

	$n = sprintf('%u', $n);
	$blocks = array(array('0.0.0.0',8), array('10.0.0.0',8), array('100.64.0.0',10), array('127.0.0.0',8), array('169.254.0.0',16), array('172.16.0.0',12), array('192.0.0.0',24), array('192.0.2.0',24), array('192.168.0.0',16), array('198.18.0.0',15), array('198.51.100.0',24), array('203.0.113.0',24), array('224.0.0.0',4), array('240.0.0.0',4));
	foreach ($blocks as $block) {
		$mask = -1 << (32 - $block[1]);
		if ((ip2long($ip) & $mask) === (ip2long($block[0]) & $mask)) {
			return false;
		}
	}

	return true;
}
function diag_headers($raw) {
	$blocks = preg_split('/\r?\n\r?\n/', trim($raw));
	$result = array();

	foreach ($blocks as $block) {
		if (!preg_match('/^HTTP\/\S+\s+\d{3}/i', trim($block))) {
			continue;
		}

		$result = array();

		foreach (preg_split('/\r?\n/', $block) as $row) {
			if (strpos($row, ':') === false) {
				continue;
			}

			list($name, $value) = explode(':', $row, 2);
			$name = strtolower(trim($name));

			if (!isset($result[$name])) {
				$result[$name] = array();
			}

			$result[$name][] = trim($value);
		}
	}

	return $result;
}
function diag_header($headers, $key) {
	return isset($headers[$key]) ? diag_value(implode(', ', $headers[$key])) : '—';
}
function diag_preview($body) {
	$s = preg_replace('/<(script|style)\b[^>]*>.*?<\/\1>/is', ' ', (string) $body);
	$s = preg_replace('/<\/(?:div|p|h[1-6]|span|strong|b|small|title|li)>/i', '; ', $s);
	$s = preg_replace('/<[^>]+>/', ' ', $s);
	$s = html_entity_decode($s, ENT_QUOTES, 'UTF-8');
	$s = trim(preg_replace('/\s+/', ' ', $s));
	$s = preg_replace('/\s*;\s*(?:;\s*)+/', '; ', $s);
	$s = trim($s, " ;\t\r\n");

	return $s === '' ? '—' : substr($s, 0, 160);
}
function diag_fields($value) {
	if (is_array($value)) {
		return diag_value(implode(', ', $value));
	}

	return is_string($value) ? diag_value($value) : '—';
}
function diag_probe($url, $kind, $marker, $ip) {
	$ch = curl_init($url);
	if (!$ch) {
		diag_line('Test', $kind);
		diag_line('Transport error', 'Cannot initialize cURL');

		return;
	}

	$headers = array('Expect:', 'Cache-Control: no-store');
	$opts    = array(
            CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false, CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 12, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'PHP2Shell-Security-Diagnostic/1.0',
            CURLOPT_ENCODING => ''
        );

	if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTPS')) {
		$opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
	}

	if ($kind !== 'GET') {
		$opts[CURLOPT_POST] = true;

		if ($kind === 'FORM') {
			$opts[CURLOPT_POSTFIELDS] = 'test_field=test_value';
			$headers[] = 'Content-Type: application/x-www-form-urlencoded';
		}
		elseif ($kind === 'MULTIPART' || $kind === 'UPLOAD') {
			/* Explicit multipart body works on PHP 5.2 without CURLFile. */
			$boundary = 'PHP2ShellDiagBoundary' . substr($marker, 0, 12);
			$part = '--' . $boundary . "\r\n";

			if ($kind === 'UPLOAD') {
				$part .= "Content-Disposition: form-data; name=\"test_file\"; filename=\"diagnostic.txt\"\r\nContent-Type: text/plain\r\n\r\nharmless diagnostic text\r\n";
			}
			else {
				$part .= "Content-Disposition: form-data; name=\"test_field\"\r\n\r\ntest_value\r\n";
			}

			$opts[CURLOPT_POSTFIELDS] = $part . '--' . $boundary . "--\r\n";
			$headers[] = 'Content-Type: multipart/form-data; boundary=' . $boundary;
		}

		$opts[CURLOPT_HTTPHEADER] = $headers;
	}

	curl_setopt_array($ch, $opts);

	$response = curl_exec($ch);
	$info     = curl_getinfo($ch);
	$err      = curl_error($ch);

	$headerSize = isset($info['header_size']) ? (int) $info['header_size'] : 0;
	$raw        = is_string($response) ? substr($response, 0, $headerSize) : '';
	$body       = is_string($response) ? substr($response, $headerSize) : false;

	curl_close($ch);

	$h          = diag_headers($raw);
	$json       = is_string($body) ? json_decode($body, true) : null;
	$executed   = is_array($json) && isset($json['executed'], $json['marker']) && $json['executed'] === true && is_string($json['marker']) && diag_equal($marker, $json['marker']);
	$status     = isset($info['http_code']) ? (int) $info['http_code'] : 0;
	$rasp       = diag_header($h, 'x-rasp-block');
	$mitigation = diag_header($h, 'cf-mitigated');
	$challenge  = is_string($body) && stripos($body, 'JavaScript required') !== false && stripos($body, 'Access Denied') !== false;

	diag_line('Test', $kind);
	diag_line('HTTP status', $status ? $status : '—');
	diag_line('Content type', isset($info['content_type']) ? diag_value($info['content_type']) : '—');
	diag_line('Duration (seconds)', isset($info['total_time']) ? $info['total_time'] : '—');
	diag_line('Target PHP executed', $executed ? 'YES' : 'NOT CONFIRMED');
	diag_line('Server', diag_header($h, 'server'));
	diag_line('Cloudflare Ray ID', diag_header($h, 'cf-ray'));
	diag_line('Cloudflare Mitigation', strtolower($mitigation) === 'challenge' ? 'challenge (Detected)' : $mitigation);
	diag_line('RASP Block', $rasp === '1' ? '1 (Detected)' : $rasp);
	diag_line('ModSecurity', diag_header($h, 'x-mod-security'));
	diag_line('LiteSpeed', diag_header($h, 'x-turbo-charged-by'));
	diag_line('LiteSpeed Cache Control', diag_header($h, 'x-litespeed-cache-control'));
	diag_line('Retry After', diag_header($h, 'retry-after'));
	diag_line('Sucuri ID', diag_header($h, 'x-sucuri-id'));
	diag_line('Request ID', diag_header($h, 'x-request-id'));
	diag_line('Redirect Location', diag_header($h, 'location'));
	diag_line('JavaScript challenge detected', $challenge ? 'YES' : 'NOT DETECTED');
	diag_line('Empty response body', $body === '' ? 'YES' : ($body === false ? 'UNKNOWN (transport failure)' : 'NO'));

	if ($err !== '' || $response === false) {
		diag_line('Transport error', $err !== '' ? $err : 'Unknown transport failure');
		diag_line('Test assessment', 'INCONCLUSIVE - transport failure');
	}
	else {
		diag_line('Test assessment', $executed ? 'TARGET EXECUTED (not proof of vulnerability)' : ($challenge ? 'INCONCLUSIVE - JavaScript challenge' : ($status >= 400 ? 'INCONCLUSIVE - HTTP rejection' : 'INCONCLUSIVE - execution not verified')));
	}

	if ($executed) {
		diag_line('Received POST fields', isset($json['post_fields']) ? diag_fields($json['post_fields']) : '—');
		diag_line('Received FILE fields', isset($json['file_fields']) ? diag_fields($json['file_fields']) : '—');
	}
	else {
		diag_line('Response preview', $body === false ? '—' : diag_preview($body));
	}

	echo "\n";
}

if (!$diagnostic_enabled || !is_string($diagnostic_secret) || strpos($diagnostic_secret, 'REPLACE_WITH_') === 0) {
	header('HTTP/1.1 404 Not Found'); exit;
}

/* Require configured access secret as HTTP Basic password. No secret in URL/logs. */
$provided = isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : '';
if (!diag_equal($diagnostic_secret, $provided)) {
	header('HTTP/1.1 401 Unauthorized');
	header('WWW-Authenticate: Basic realm="PHP2Shell Diagnostic"');
	echo "Authentication required.\n";

	exit;
}

/* Never use an untrusted Host header as the destination. Require explicit HTTPS origin. */
$parsed = parse_url($diagnostic_base_url);
if (!is_array($parsed) || !isset($parsed['scheme'], $parsed['host']) || strtolower($parsed['scheme']) !== 'https' || isset($parsed['user']) || isset($parsed['pass']) || isset($parsed['path']) || isset($parsed['query']) || isset($parsed['fragment']) || isset($parsed['port']) || !preg_match('/^[a-z0-9.-]+$/iD', $parsed['host'])) {
	diag_line('Configuration error', 'Set diagnostic_base_url to an HTTPS origin, e.g. https://your-domain.example'); exit;
}

$host = strtolower($parsed['host']);
$ip   = gethostbyname($host);
if ($ip === $host || !diag_public_ipv4($ip)) {
	diag_line('Configuration error', 'Target hostname must resolve to a public IPv4 address'); exit;
}

/* PHP 5.2 cURL cannot pin DNS with CURLOPT_RESOLVE. Explicit HTTPS origin + no redirects is a baseline, not a complete DNS-rebinding defence. */
$path = rtrim(str_replace('\\', '/', dirname(isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/')), '/');
if ($path === '.') {
	$path = '';
}

$marker = md5(uniqid(mt_rand(), true)); /* Request correlation only, not a security token. */
$sig    = hash_hmac('sha1', $marker, $diagnostic_secret);
$url    = $diagnostic_base_url . $path . '/php2shell-target.php?marker=' . $marker . '&sig=' . $sig;

diag_line('Diagnostic', 'PHP2Shell benign request-handling diagnostic');
diag_line('Timestamp (UTC)', gmdate('c'));
diag_line('PHP version', PHP_VERSION);
diag_line('PHP SAPI', PHP_SAPI);
diag_line('Operating system', PHP_OS);
diag_line('Server software', isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '(unavailable)');

foreach (array('session.upload_progress.enabled','session.upload_progress.cleanup','file_uploads','enable_post_data_reading','post_max_size','upload_max_filesize','max_file_uploads','max_input_vars','memory_limit','max_execution_time','open_basedir','disable_functions','allow_url_include','expose_php') as $key) {
	if ($key === 'disable_functions' || $key === 'open_basedir') {
		diag_line($key, diag_cfg($key) === '(empty)' ? '(empty)' : '(configured; value hidden)');
	}
	else {
		diag_line($key, diag_cfg($key));
	}
}

diag_line('cURL extension', extension_loaded('curl') ? 'YES' : 'NO');
diag_line('OpenSSL extension', extension_loaded('openssl') ? 'YES' : 'NO');

echo "\nNOTE: Benign requests do not establish CVE exploitability or patch status.\n\n";

if (!extension_loaded('curl')) {
	exit;
}

foreach (array('GET', 'FORM', 'MULTIPART', 'UPLOAD') as $kind) {
	diag_probe($url, $kind, $marker, $ip);
}

echo "INTERPRETATION\n";
echo "- A RASP block or Cloudflare challenge indicates request filtering, not confirmed PHP2Shell protection.\n";
echo "- Successful multipart handling does not establish vulnerability.\n";
echo "- Verify PHP security patch status with the hosting provider.\n";
echo "- Remove all diagnostic files after testing.\n";
