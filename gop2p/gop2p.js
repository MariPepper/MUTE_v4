// Files are encrypted in the browser (AES-GCM).
// Normal upload: the server keeps the encrypted copy (+ key) as a fallback when the uploader is offline.
// P2P only: nothing is stored on the server; the key only travels over the WebRTC data channel.
const peerId = Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(36).padStart(2, '0')).join('');
const scriptEl = document.querySelector('script[data-expiry-time]');
const EXPIRY_TIME = Number(scriptEl.dataset.expiryTime);
const MAX_FILE_SIZE = Number(scriptEl.dataset.maxFileSize);
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
const ICE = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:stun4.l.google.com:19302' },
        { urls: 'stun:stun.stunprotocol.org:3478' }
    ],
    iceCandidatePoolSize: 10
};
const CHUNK = 16 * 1024;
const POLL_MS = 400; // signaling poll interval

const files = new Map();    // serverFilename -> { name, type, blob, keyB64, time, p2p } (uploaded from this tab)
const sessions = new Map(); // remote peerId -> SimplePeer
let currentList = [];

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------
function toB64Url(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64Url(str) {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(bin, c => c.charCodeAt(0));
}

// Returns { blob: iv || ciphertext, keyB64 }
async function encryptFile(file) {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, await file.arrayBuffer()));
    const out = new Uint8Array(12 + ct.length);
    out.set(iv, 0);
    out.set(ct, 12);
    const keyB64 = toB64Url(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
    return { blob: new Blob([out]), keyB64 };
}

async function decryptBytes(bytes, keyB64) {
    const raw = fromB64Url(keyB64);
    if (raw.length !== 32) throw new Error('Invalid key');
    const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, key, bytes.subarray(12));
}

function saveFile(buffer, name, type) {
    const url = URL.createObjectURL(new Blob([buffer], { type }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Delay revocation so Firefox inside an iframe can finish reading the blob
    setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ---------------------------------------------------------------------------
// File list
// ---------------------------------------------------------------------------
async function fetchFileList() {
    try {
        const response = await fetch('?list=1');
        if (!response.ok) {
            console.error(`Failed to fetch file list: ${response.status}`);
            return;
        }
        currentList = await response.json();
        updateFileList(currentList);
    } catch (err) {
        console.error('fetchFileList error:', err);
    }
}

function emptyMessage() {
    const div = document.createElement('div');
    div.className = 'message';
    div.textContent = 'No files available.';
    return div;
}

function buildItem(file) {
    const div = document.createElement('div');
    div.className = 'message';
    div.dataset.filename = file.filename;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'message-name';
    nameSpan.textContent = file.name;

    const textSpan = document.createElement('span');
    textSpan.className = 'message-text';

    const link = document.createElement('a');
    link.href = '#';
    link.className = 'open-btn';
    link.dataset.filename = file.filename;
    link.dataset.peerId = file.peerId;
    link.dataset.mimeType = file.type;
    link.dataset.name = file.name;
    link.dataset.p2p = file.p2p ? '1' : '';
    link.textContent = 'Download';
    link.addEventListener('click', handleDownload);

    const expiry = document.createElement('span');
    expiry.className = 'expiry';

    textSpan.append(link, expiry);
    div.append(nameSpan, textSpan);
    return div;
}

// Update file list dynamically without flickering
function updateFileList(list) {
    const fileList = document.getElementById('fileList');
    const existing = new Map(
        Array.from(fileList.querySelectorAll('.message[data-filename]')).map(el => [el.dataset.filename, el])
    );

    if (!list || list.length === 0) {
        if (existing.size > 0 || !fileList.firstChild) fileList.replaceChildren(emptyMessage());
        return;
    }

    const noFiles = fileList.querySelector('.message:not([data-filename])');
    if (noFiles) noFiles.remove();

    list.forEach(file => {
        let el = existing.get(file.filename);
        if (el) {
            existing.delete(file.filename);
        } else {
            el = buildItem(file);
            fileList.prepend(el);
            console.log(`Added new file: ${file.filename}`);
        }
        el.dataset.expiresAt = String(Date.now() + file.expires_in * 1000);
    });

    // Remove files that no longer exist
    existing.forEach(el => {
        el.remove();
        console.log(`Removed old file: ${el.dataset.filename}`);
    });

    updateExpirationCountdown();
}

// Update expiration countdowns client-side
function updateExpirationCountdown() {
    document.querySelectorAll('#fileList .message[data-filename]').forEach(el => {
        const seconds = Math.round((Number(el.dataset.expiresAt) - Date.now()) / 1000);
        if (seconds <= 0) {
            el.remove();
        } else {
            el.querySelector('.expiry').textContent = ` (Expires in ${seconds} seconds)`;
        }
    });
}

// Show feedback message
function showFeedback(message, isError = false) {
    const feedbackDiv = document.createElement('div');
    feedbackDiv.className = isError ? 'error' : 'success';
    feedbackDiv.textContent = message;
    const contentDiv = document.querySelector('.content');
    contentDiv.insertBefore(feedbackDiv, contentDiv.firstChild);
    setTimeout(() => feedbackDiv.remove(), 4000);
}

// ---------------------------------------------------------------------------
// Signaling (signal.php works as a mailbox per peer)
// ---------------------------------------------------------------------------
async function postSignal(to, signal) {
    const response = await fetch('signal.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to, from: peerId, signal })
    });
    if (!response.ok) throw new Error(`Failed to send signaling data: ${response.status}`);
}

// The "o=" line of an SDP keeps the same session id for the whole life of one RTCPeerConnection,
// so it tells a renegotiation of the same connection apart from a brand new attempt.
function offerKey(sdp) {
    const m = /^o=\S+\s+(\S+)/m.exec(sdp || '');
    return m ? m.at(1) : '';
}

let polling = false;
async function pollSignals() {
    if (polling) return;
    polling = true;
    try {
        const response = await fetch(`signal.php?peerId=${encodeURIComponent(peerId)}`);
        if (!response.ok) return;
        for (const { from, signal } of await response.json()) {
            try {
                const peer = sessions.get(from);
                const alive = peer && !peer.destroyed;
                if (signal && signal.type === 'offer') {
                    const key = offerKey(signal.sdp);
                    if (alive && peer._offerKey === key) {
                        peer.signal(signal); // renegotiation inside the same connection
                    } else {
                        // a NEW attempt from this peer: drop the old one first
                        if (alive) peer.destroy();
                        const fresh = acceptPeer(from); // someone wants one of my files
                        fresh._offerKey = key;
                        fresh.signal(signal);
                    }
                } else if (alive) {
                    peer.signal(signal);
                }
            } catch (err) {
                console.error('Signal error:', err);
            }
        }
    } catch (err) {
        console.error('Failed to fetch signaling data:', err);
    } finally {
        polling = false;
    }
}

// ---------------------------------------------------------------------------
// P2P transfer. Frames: [1 byte type][payload]  (1 = JSON, 2 = file chunk)
// ---------------------------------------------------------------------------
const T_JSON = 1;
const T_DATA = 2;

function frame(type, bytes) {
    const out = new Uint8Array(bytes.length + 1);
    out.set([type], 0);
    out.set(bytes, 1);
    return out;
}

function jsonFrame(obj) {
    return frame(T_JSON, enc.encode(JSON.stringify(obj)));
}

function writeFrame(peer, data) {
    if (peer.destroyed) return Promise.reject(new Error('Connection closed'));
    if (peer.write(data)) return Promise.resolve();
    return new Promise((resolve, reject) => {
        const onDrain = () => { peer.removeListener('close', onClose); resolve(); };
        const onClose = () => { peer.removeListener('drain', onDrain); reject(new Error('Connection closed')); };
        peer.once('drain', onDrain);
        peer.once('close', onClose);
    });
}

// Uploader side: answer requests for files uploaded from this tab
function acceptPeer(from) {
    const peer = new SimplePeer({ config: ICE });
    sessions.set(from, peer);

    peer.on('signal', signal => postSignal(from, signal).catch(err => console.error(err)));
    const drop = () => { if (sessions.get(from) === peer) sessions.delete(from); };
    peer.on('error', err => { console.error('WebRTC peer error:', err); drop(); });
    peer.on('close', drop);
    peer.on('connect', () => console.log('WebRTC connection established as uploader'));

    peer.on('data', async (data) => {
        try {
            const bytes = new Uint8Array(data);
            if (bytes.at(0) !== T_JSON) return;
            const { filename } = JSON.parse(dec.decode(bytes.subarray(1)));
            console.log('Uploader received request for:', filename);

            const item = files.get(filename);
            if (!item) {
                await writeFrame(peer, jsonFrame({ error: 'File not found' }));
                return;
            }
            const all = new Uint8Array(await item.blob.arrayBuffer());
            await writeFrame(peer, jsonFrame({ size: all.length, key: item.keyB64 }));
            for (let i = 0; i < all.length; i += CHUNK) {
                await writeFrame(peer, frame(T_DATA, all.subarray(i, i + CHUNK)));
            }
            console.log('Sent file to peer:', filename);
        } catch (err) {
            console.error('Failed to send file data:', err);
        }
    });
    return peer;
}

// Downloader side: resolves { bytes, keyB64 } (still encrypted)
function downloadFromPeer(owner, filename, connectTimeout = 10000) {
    return new Promise((resolve, reject) => {
        const previous = sessions.get(owner);
        if (previous) previous.destroy();

        const peer = new SimplePeer({ initiator: true, config: ICE });
        sessions.set(owner, peer);

        let size = 0;
        let keyB64 = null;
        let got = 0;
        let settled = false;
        let connected = false;
        let lastIce = 'none';
        const parts = [];
        peer.on('iceStateChange', (ice) => { lastIce = ice; });

        const finish = (err, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (sessions.get(owner) === peer) sessions.delete(owner);
            setTimeout(() => peer.destroy(), 200);
            if (err) reject(err); else resolve(value);
        };
        let timer = setTimeout(() => finish(new Error('WebRTC connection timed out after ' + (connectTimeout / 1000) + ' seconds')), connectTimeout);

        peer.on('error', err => { console.error('WebRTC peer error:', err); finish(err); });
        peer.on('close', () => finish(new Error('Connection closed (ICE: ' + lastIce + ', connected: ' + connected + ')')));
        peer.on('signal', signal => postSignal(owner, signal).catch(finish));

        peer.on('connect', () => {
            console.log('WebRTC connection established with peer:', owner);
            connected = true;
            clearTimeout(timer);
            timer = setTimeout(() => finish(new Error('Transfer timed out')), 60000);
            peer.write(jsonFrame({ filename }));
        });

        peer.on('data', (data) => {
            try {
                const bytes = new Uint8Array(data); // copy
                const type = bytes.at(0);
                const payload = bytes.subarray(1);

                if (type === T_JSON) {
                    const header = JSON.parse(dec.decode(payload));
                    if (header.error || !Number.isInteger(header.size) || header.size <= 0 ||
                        header.size > MAX_FILE_SIZE + 1024 || typeof header.key !== 'string') {
                        return finish(new Error(header.error || 'Invalid response'));
                    }
                    size = header.size;
                    keyB64 = header.key;
                } else if (type === T_DATA && size) {
                    parts.push(payload);
                    got += payload.length;
                    if (got > size) return finish(new Error('Received more data than expected'));
                    if (got === size) {
                        const all = new Uint8Array(size);
                        let offset = 0;
                        for (const part of parts) { all.set(part, offset); offset += part.length; }
                        finish(null, { bytes: all, keyB64 });
                    }
                }
            } catch (err) {
                console.error('Data processing error:', err);
                finish(err);
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------
// Server fallback: fetch the encrypted blob and decrypt it here
async function serverDownload(filename, keyB64, name, type) {
    const response = await fetch(`?download=${encodeURIComponent(filename)}`);
    if (!response.ok) throw new Error(`Server download failed: ${response.status}`);
    saveFile(await decryptBytes(new Uint8Array(await response.arrayBuffer()), keyB64), name, type);
}

async function handleDownload(e) {
    e.preventDefault();
    const btn = e.currentTarget;
    if (btn.dataset.downloading === '1') return;
    btn.dataset.downloading = '1';

    const { filename, peerId: owner, name, mimeType, p2p } = btn.dataset;
    console.log('Download initiated for:', filename, 'Peer ID:', owner);

    // A server copy only exists when the file was not uploaded as "P2P only"
    const listed = currentList.find(f => f.filename === filename);
    const serverKey = listed && !listed.p2p && listed.key ? listed.key : null;

    try {
        // Uploaded from this tab: decrypt the local copy
        const own = files.get(filename);
        if (own) {
            saveFile(await decryptBytes(new Uint8Array(await own.blob.arrayBuffer()), own.keyB64), name, mimeType);
            return;
        }

        // 1) Peer-to-peer through the signaling server (shorter wait if the server can take over)
        let p2pError = null;
        if (owner && owner !== peerId) {
            showFeedback('Connecting to uploader...');
            try {
                const result = await downloadFromPeer(owner, filename, serverKey ? 6000 : 10000);
                saveFile(await decryptBytes(result.bytes, result.keyB64), name, mimeType);
                return;
            } catch (err) {
                console.warn('P2P download failed:', err);
                p2pError = err;
            }
        }

        // 2) Server copy
        if (serverKey) {
            await serverDownload(filename, serverKey, name, mimeType);
            return;
        }

        showFeedback(
            (p2p ? 'Could not reach the uploader. This file is P2P only.' : 'Could not reach the uploader.') +
            (p2pError ? ' (' + p2pError.message + ')' : ''),
            true
        );
    } catch (err) {
        console.error('Download error:', err);
        showFeedback('Download failed: ' + err.message, true);
    } finally {
        delete btn.dataset.downloading;
    }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function () {
    setInterval(pollSignals, POLL_MS);

    const fileInput = document.getElementById('file');
    document.getElementById('clearBtn').addEventListener('click', () => { fileInput.value = ''; });

    // Handle file upload
    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const file = fileInput.files.item(0);
        if (!file) {
            showFeedback('No file selected.', true);
            return;
        }
        if (file.size > MAX_FILE_SIZE) {
            showFeedback('File size exceeds 10MB limit.', true);
            return;
        }
        if (!ALLOWED_TYPES.includes(file.type)) {
            showFeedback('Invalid file type. Allowed: JPEG, PNG, GIF, PDF.', true);
            return;
        }

        try {
            const p2pOnly = document.getElementById('p2pOnly').checked;
            const { blob, keyB64 } = await encryptFile(file);

            const formData = new FormData();
            if (p2pOnly) {
                formData.append('p2p', '1'); // listed in the gallery, nothing stored on the server
            } else {
                formData.append('file', blob, 'enc.bin');
                formData.append('key', keyB64); // gallery is public: the server hands the key to downloaders (fallback)
            }
            formData.append('name', file.name);
            formData.append('type', file.type);
            formData.append('peerId', peerId);

            const response = await fetch('', { method: 'POST', body: formData });
            const responseData = await response.json();
            if (response.ok && responseData.success) {
                console.log('File uploaded, server filename:', responseData.filename);
                files.set(responseData.filename, { name: file.name, type: file.type, blob, keyB64, time: Date.now(), p2p: p2pOnly });
                fetchFileList();
                showFeedback(p2pOnly
                    ? `${file.name} is listed as P2P only. Keep this tab open: it is the only source.`
                    : `File uploaded successfully: ${file.name}. Keep this tab open so others can download directly from you.`);
                fileInput.value = '';
            } else {
                showFeedback('Server upload failed: ' + (responseData.error || 'Unknown error'), true);
            }
        } catch (err) {
            console.error('Upload error:', err);
            showFeedback('Upload failed: ' + err.message, true);
        }
    });

    // Start polling for file list updates
    fetchFileList();
    let pollInterval = setInterval(fetchFileList, 3000);

    // Pause polling when tab is inactive
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            clearInterval(pollInterval);
            console.log('Paused polling: tab inactive');
        } else {
            pollInterval = setInterval(fetchFileList, 3000);
            fetchFileList();
            console.log('Resumed polling: tab active');
        }
    });

    // Update expiration countdown every second
    setInterval(updateExpirationCountdown, 1000);
});

// Clean up expired files client-side
setInterval(() => {
    const now = Date.now();
    files.forEach((fileData, filename) => {
        if (now - fileData.time > EXPIRY_TIME) {
            files.delete(filename);
            console.log('Expired file removed:', filename);
        }
    });
}, 1000);
