<?php
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');

require dirname(__FILE__) . '/php2shell-config.php';

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

if (!$diagnostic_enabled || !is_string($diagnostic_secret) || strlen($diagnostic_secret) < 32 || strpos($diagnostic_secret, 'REPLACE_WITH_') === 0) {
	header('HTTP/1.1 404 Not Found');
	exit;
}

$marker    = isset($_GET['marker']) ? $_GET['marker'] : '';
$signature = isset($_GET['sig']) ? $_GET['sig'] : '';

if (!is_string($marker) || !preg_match('/^[a-f0-9]{32}$/D', $marker) || !is_string($signature) || !preg_match('/^[a-f0-9]{40}$/D', $signature) || !diag_equal(hash_hmac('sha1', $marker, $diagnostic_secret), $signature)) {
	header('HTTP/1.1 403 Forbidden');
	echo json_encode(array('executed' => false, 'error' => 'Invalid diagnostic authorization'));
	exit;
}

echo json_encode(array('executed' => true, 'marker' => $marker, 'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '', 'content_type' => isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '', 'post_fields' => array_keys($_POST), 'file_fields' => array_keys($_FILES)));
