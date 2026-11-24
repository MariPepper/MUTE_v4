<?php
declare(strict_types=1);

define('SIGNAL_DIR', __DIR__ . '/gallery/signals/');
define('EXPIRY_TIME', 300); // 5 minutes, match gallery.php
define('MAX_QUEUE', 200);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-Robots-Tag: noindex, nofollow');
header('Referrer-Policy: no-referrer');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none';");

function out($data, int $status = 200): void {
    http_response_code($status);
    echo json_encode($data);
    exit;
}

function isId($v): bool {
    return is_string($v) && preg_match('/^[a-z0-9]{6,32}$/', $v) === 1;
}

// Ensure signals directory exists
if (!is_dir(SIGNAL_DIR) && !mkdir(SIGNAL_DIR, 0750, true)) {
    out(['error' => 'Failed to create signals directory'], 500);
}

// Clean up expired signaling data
foreach (glob(SIGNAL_DIR . '*.json') ?: [] as $file) {
    if (time() - filemtime($file) > EXPIRY_TIME) @unlink($file);
}

// Each peer has a mailbox (a queue of {from, signal}); messages are removed once read
function withQueue(string $peerId, callable $fn) {
    $fp = fopen(SIGNAL_DIR . $peerId . '.json', 'c+');
    if (!$fp) out(['error' => 'Failed to open mailbox'], 500);
    flock($fp, LOCK_EX);
    $queue = json_decode((string) stream_get_contents($fp), true);
    if (!is_array($queue)) $queue = [];
    $now = time();
    $queue = array_values(array_filter($queue, fn($m) => $now - ($m['time'] ?? 0) <= EXPIRY_TIME));
    [$queue, $result] = $fn($queue);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($queue));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $result;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Send a signal: { to, from, signal }
    $data = json_decode((string) file_get_contents('php://input', false, null, 0, 16384), true);
    $to = $data['to'] ?? '';
    $from = $data['from'] ?? '';
    $signal = $data['signal'] ?? null;

    if (!isId($to) || !isId($from) || !is_array($signal) || strlen(json_encode($signal)) > 8192) {
        out(['error' => 'Invalid request'], 400);
    }

    withQueue($to, function (array $queue) use ($from, $signal): array {
        $queue[] = ['from' => $from, 'signal' => $signal, 'time' => time()];
        return [array_slice($queue, -MAX_QUEUE), true];
    });
    out(['success' => true]);

} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Read (and clear) my mailbox
    $peerId = $_GET['peerId'] ?? '';
    if (!isId($peerId)) out(['error' => 'Invalid peerId'], 400);
    if (!is_file(SIGNAL_DIR . $peerId . '.json')) out([]);

    out(withQueue($peerId, fn(array $queue) => [
        [],
        array_map(fn($m) => ['from' => $m['from'], 'signal' => $m['signal']], $queue)
    ]));

} else {
    out(['error' => 'Method not allowed'], 405);
}