<?php
declare(strict_types=1);

// Configuration
define('UPLOAD_DIR', __DIR__ . '/gallery/');
define('METADATA_FILE', UPLOAD_DIR . 'files.json');
define('MAX_FILE_SIZE', 10 * 1024 * 1024); // 10MB
define('EXPIRY_TIME', 300); // 5 minutes in seconds
define('ALLOWED_TYPES', ['image/jpeg', 'image/png', 'image/gif', 'application/pdf']);

ini_set('display_errors', '0');
error_reporting(E_ALL);

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

// Ensure upload directory exists and is not reachable directly from the web
if (!is_dir(UPLOAD_DIR) && !mkdir(UPLOAD_DIR, 0750, true)) {
    jsonOut(['error' => 'Failed to create gallery directory'], 500);
}
if (!file_exists(UPLOAD_DIR . '.htaccess')) {
    file_put_contents(UPLOAD_DIR . '.htaccess', "Require all denied\n");
}
if (!file_exists(METADATA_FILE)) {
    file_put_contents(METADATA_FILE, '[]', LOCK_EX);
}

// Read-modify-write of files.json under an exclusive lock
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

// Clean up expired files
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

// Upload: the browser sends the already-encrypted blob.
// Normal mode: the blob is stored and the key is kept too, so anyone in the public gallery
//              can use the server copy as a fallback when the uploader is offline.
// P2P only:    nothing is stored (no blob, no key); the file only lives in the uploader's tab.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
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
        if ($file['size'] > MAX_FILE_SIZE + 1024) { // +overhead of IV and auth tag
            jsonOut(['error' => 'File size exceeds 10MB limit.'], 413);
        }
    }
    if (!in_array($type, ALLOWED_TYPES, true)) {
        jsonOut(['error' => 'Invalid file type. Allowed: JPEG, PNG, GIF, PDF.'], 415);
    }
    // AES-256 key = 32 bytes = 43 chars in base64url
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
    withMetadata(function (array $meta) use ($filename, $name, $type, $peerId, $p2pOnly, $key): array {
        $meta[$filename] = [
            'name' => $name,
            'type' => $type,
            'time' => time(),
            'peerId' => $peerId,
            'p2p' => $p2pOnly,
            'key' => $p2pOnly ? '' : $key
        ];
        return $meta;
    });
    jsonOut(['success' => true, 'filename' => $filename]);
}

// Download (server fallback): returns the encrypted blob, decrypted in the browser
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

// File list (replaces direct access to gallery/files.json)
if (isset($_GET['list'])) {
    $now = time();
    $list = [];
    foreach ($metadata as $filename => $info) {
        $isP2p = !empty($info['p2p']);
        $list[] = [
            'filename' => $filename,
            'name' => $info['name'],
            'type' => $info['type'],
            'peerId' => $info['peerId'] ?? '',
            'p2p' => $isP2p,
            'key' => $isP2p ? '' : ($info['key'] ?? ''), // never exposed for P2P-only files
            'expires_in' => EXPIRY_TIME - ($now - $info['time'])
        ];
    }
    jsonOut($list);
}

// Generate a random nonce for CSP
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