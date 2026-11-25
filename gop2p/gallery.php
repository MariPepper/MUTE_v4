<?php
declare(strict_types=1);

// Configuration
define('UPLOAD_DIR', __DIR__ . '/gallery/');
define('METADATA_FILE', UPLOAD_DIR . 'files.json');
define('MAX_FILE_SIZE', 10 * 1024 * 1024); // 10MB
define('EXPIRY_TIME', 300); // 5 minutes in seconds
define('ALLOWED_TYPES', ['image/jpeg', 'image/png', 'image/gif', 'application/pdf']);
// Server secret for metadata encryption. Keep OUTSIDE the web root if possible.
define('SERVER_SECRET_FILE', dirname(__DIR__) . '/.gop2p_secret');

ini_set('display_errors', '0');
error_reporting(E_ALL);

session_start();
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf'];

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-Robots-Tag: noindex, nofollow');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

function jsonOut($data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}

// ---------------------------------------------------------------------------
// Server secret (used only for metadata encryption)
// ---------------------------------------------------------------------------
function serverSecret(): string {
    if (is_file(SERVER_SECRET_FILE)) {
        return trim((string) file_get_contents(SERVER_SECRET_FILE));
    }
    $secret = bin2hex(random_bytes(32));
    if (@file_put_contents(SERVER_SECRET_FILE, $secret, LOCK_EX) === false) {
        jsonOut(['error' => 'Cannot create server secret'], 500);
    }
    @chmod(SERVER_SECRET_FILE, 0600);
    return $secret;
}

function encryptMeta(string $plaintext, string $filename): string {
    $key = hash_hmac('sha256', 'meta:' . $filename, serverSecret(), true);
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $ct);
}

function decryptMeta(string $b64, string $filename): ?string {
    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < 28) return null;
    $key = hash_hmac('sha256', 'meta:' . $filename, serverSecret(), true);
    $iv = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $ct = substr($raw, 28);
    $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $pt === false ? null : $pt;
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------
if (!is_dir(UPLOAD_DIR) && !mkdir(UPLOAD_DIR, 0750, true)) {
    jsonOut(['error' => 'Failed to create gallery directory'], 500);
}
if (!file_exists(UPLOAD_DIR . '.htaccess')) {
    file_put_contents(UPLOAD_DIR . '.htaccess', "Require all denied\n");
}
if (!file_exists(METADATA_FILE)) {
    file_put_contents(METADATA_FILE, '[]', LOCK_EX);
}

function withMetadata(callable $fn): array {
    $fp = fopen(METADATA_FILE, 'c+');
    if (!$fp) jsonOut(['error' => 'Cannot open metadata'], 500);
    flock($fp, LOCK_EX);
    $meta = json_decode((string) stream_get_contents($fp), true);
    if (!is_array($meta)) $meta = [];
    $meta = $fn($meta);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($meta));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $meta;
}

function cleanExpiredFiles(): array {
    return withMetadata(function (array $meta): array {
        $now = time();
        foreach ($meta as $filename => $info) {
            if ($now - ($info['time'] ?? 0) > EXPIRY_TIME) {
                @unlink(UPLOAD_DIR . $filename);
                unset($meta[$filename]);
            }
        }
        return $meta;
    });
}
$metadata = cleanExpiredFiles();

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $sent = $_POST['csrf'] ?? '';
    $expected = $_SESSION['csrf'] ?? '';
    if ($sent === '' || $expected === '' || !hash_equals($expected, $sent)) {
        jsonOut(['error' => 'csrf'], 403);
    }
    $file = $_FILES['file'] ?? null;
    $p2pOnly = ($_POST['p2p'] ?? '') === '1';
    $type = (string) ($_POST['type'] ?? '');
    $peerId = (string) ($_POST['peerId'] ?? '');
    $key = (string) ($_POST['key'] ?? '');
    $name = basename(str_replace('\\', '/', (string) ($_POST['name'] ?? '')));
    $name = preg_replace('/[\x00-\x1F\x7F]+/', '', $name);

    if (!$p2pOnly) {
        if (!$file || $file['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'])) {
            jsonOut(['error' => 'Upload error'], 400);
        }
        if ($file['size'] > MAX_FILE_SIZE + 1024) {
            jsonOut(['error' => 'File size exceeds 10MB limit.'], 413);
        }
    }
    if (!in_array($type, ALLOWED_TYPES, true)) {
        jsonOut(['error' => 'Invalid file type. Allowed: JPEG, PNG, GIF, PDF.'], 415);
    }
    if (!$p2pOnly && !preg_match('/^[A-Za-z0-9_-]{43}$/', $key)) {
        jsonOut(['error' => 'Invalid key'], 400);
    }
    if (!preg_match('/^[a-z0-9]{6,32}$/', $peerId)) $peerId = '';
    $name = preg_match('/^.{1,200}/su', $name, $m) ? $m[0] : 'file';

    if ($p2pOnly && $peerId === '') {
        jsonOut(['error' => 'Invalid peerId'], 400);
    }

    $filename = bin2hex(random_bytes(8)) . '.enc';
    if (!$p2pOnly && !move_uploaded_file($file['tmp_name'], UPLOAD_DIR . $filename)) {
        jsonOut(['error' => 'Failed to save file.'], 500);
    }

    // Encrypt PII metadata. Keep the key in plain (protected by .htaccess).
    $nameEnc = encryptMeta($name, $filename);
    $typeEnc = encryptMeta($type, $filename);
    $peerEnc = encryptMeta($peerId, $filename);

    withMetadata(function (array $meta) use ($filename, $nameEnc, $typeEnc, $peerEnc, $p2pOnly, $key): array {
        $meta[$filename] = [
            'name_enc' => $nameEnc,
            'type_enc' => $typeEnc,
            'peer_enc' => $peerEnc,
            'time' => time(),
            'p2p' => $p2pOnly,
            'key' => $p2pOnly ? '' : $key  // plain, same as before — .htaccess protects it
        ];
        return $meta;
    });
    jsonOut(['success' => true, 'filename' => $filename]);
}

// ---------------------------------------------------------------------------
// Download (server fallback)
// ---------------------------------------------------------------------------
if (isset($_GET['download'])) {
    $filename = (string) $_GET['download'];
    if (!preg_match('/^[a-f0-9]{16}\.enc$/', $filename) || !isset($metadata[$filename]) || !is_file(UPLOAD_DIR . $filename)) {
        jsonOut(['error' => 'File not found or expired.'], 404);
    }
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . filesize(UPLOAD_DIR . $filename));
    header('Content-Disposition: attachment; filename="enc.bin"');
    readfile(UPLOAD_DIR . $filename);
    exit;
}

// ---------------------------------------------------------------------------
// File list
// ---------------------------------------------------------------------------
if (isset($_GET['list'])) {
    $now = time();
    $list = [];
    foreach ($metadata as $filename => $info) {
        $isP2p = !empty($info['p2p']);
        $name = decryptMeta($info['name_enc'] ?? '', $filename) ?? 'unknown';
        $type = decryptMeta($info['type_enc'] ?? '', $filename) ?? 'application/octet-stream';
        $peer = decryptMeta($info['peer_enc'] ?? '', $filename) ?? '';
        $list[] = [
            'filename' => $filename,
            'name' => $name,
            'type' => $type,
            'peerId' => $peer,
            'p2p' => $isP2p,
            'key' => $isP2p ? '' : ($info['key'] ?? ''),  // same key the browser sent
            'expires_in' => EXPIRY_TIME - ($now - ($info['time'] ?? 0))
        ];
    }
    jsonOut($list);
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------
$nonce = base64_encode(random_bytes(16));
header('Content-Type: text/html; charset=utf-8');
header("Content-Security-Policy: default-src 'self' blob:; script-src 'self' 'nonce-$nonce' https://unpkg.com; style-src 'self'; font-src 'self'; img-src 'self' blob: data:; connect-src 'self' blob: frame-ancestors 'self'; object-src 'none'; https: wss:;");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>P2P File Transfer Gallery</title>
    <link rel="stylesheet" href="style-8.css">
    <script src="https://unpkg.com/simple-peer@9.11.0/simplepeer.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">P2P File Transfer Gallery</div>
        <div class="content">
            <p>The maximum file size allowed by this application is 10 MB.</p>

            <form class="chat-form" id="uploadForm">
                <div class="form-group">
                    <input type="file" name="file" id="file" accept="image/jpeg,image/png,image/gif,application/pdf" required>
                </div>
                <input type="hidden" id="csrf-token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES); ?>">
                <div class="form-group">
                    <label><input type="checkbox" id="p2pOnly"> P2P only (don't store on the server)</label>
                </div>
                <div class="button-group">
                    <button type="submit" class="submit-btn">Upload File</button>
                    <button type="button" class="clear-btn" id="clearBtn">Clear</button>
                </div>
                <hr>
            </form>

            <div class="chat-box" id="fileList">
                <div class="message">No files available.</div>
            </div>
        </div>
    </div>

    <script nonce="<?php echo $nonce; ?>" src="gop2p.js" data-expiry-time="<?php echo EXPIRY_TIME * 1000; ?>" data-max-file-size="<?php echo MAX_FILE_SIZE; ?>"></script>
</body>
</html>
