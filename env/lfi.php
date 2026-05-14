<?php
// Intentionally vulnerable local-file-read endpoint for the lab.
$path = $_GET['file'] ?? '/proc/self/maps';
$offset = isset($_GET['offset']) ? max(0, intval($_GET['offset'])) : 0;
$length = isset($_GET['length']) ? max(0, min(1048576, intval($_GET['length']))) : null;

header('Content-Type: application/octet-stream');

$fh = @fopen($path, 'rb');
if ($fh === false) {
    http_response_code(404);
    exit;
}

if ($offset > 0) {
    fseek($fh, $offset);
}

if ($length === null) {
    fpassthru($fh);
    fclose($fh);
    exit;
}

$remaining = $length;
while ($remaining > 0 && !feof($fh)) {
    $chunk = fread($fh, min(65536, $remaining));
    if ($chunk === false || $chunk === '') {
        break;
    }
    $remaining -= strlen($chunk);
    echo $chunk;
}

fclose($fh);
