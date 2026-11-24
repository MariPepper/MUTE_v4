<?php
$nonce = base64_encode(random_bytes(16));

header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-Robots-Tag: noindex, nofollow');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header("Content-Security-Policy: default-src 'self' blob:; script-src 'self' 'nonce-$nonce'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; connect-src 'self' blob:; frame-src 'self' blob:; frame-ancestors 'self'; object-src 'none';");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Metadata Scrambler</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h1>Metadata Scrambler</h1>
    <p>Upload a file to scramble its metadata. Supported formats: JPEG, PNG, GIF, BMP, WebP, PDF, MP3, DOC, DOCX.</p>
    <p>The maximum file size allowed by this application is 10 MB.</p>
    <div id="dropZone">Drag & drop files here or click to upload</div>
    <input type="file" id="fileInput" multiple accept="image/jpeg,image/png,image/gif,image/bmp,image/webp,application/pdf,audio/mpeg,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document">
    <div id="status"></div>
    <div id="metadata-container"></div>
    <script nonce="<?php echo $nonce; ?>" src="script.js"></script>
</body>
</html>