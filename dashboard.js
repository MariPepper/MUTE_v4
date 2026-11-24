// Tool configuration
const tools = {
    home: {
        title: 'Dashboard Overview',
        icon: '🏠',
        breadcrumb: 'Privacy Tools > Dashboard',
        url: null
    },
    chat: {
        title: 'Encrypted Chat (MUTE)',
        icon: '💬',
        breadcrumb: 'Privacy Tools > Encrypted Chat',
        url: './mute/enter.php'
    },
    scrambler: {
        title: 'Metadata Scrambler',
        icon: '🧩',
        breadcrumb: 'Privacy Tools > Metadata Scrambler',
        url: './scrambler/index.php'
    },
    transfer: {
        title: 'P2P File Transfer',
        icon: '🔗',
        breadcrumb: 'Privacy Tools > P2P Transfer',
        url: './gop2p/gallery.php',
    },
    proxy: {
        title: 'Proxy Chains',
        icon: '🛡️',
        breadcrumb: 'Privacy Tools > Proxy Chains',
        url: './proxies/index.php'
    },
    tempmail: {
        title: 'Temporary Mail',
        icon: '✉️',
        breadcrumb: 'Privacy Tools > Temporary Mail',
        url: './tempmail/index.php'
    },
    about: {
        title: 'About Privacy Tools',
        icon: 'ℹ️',
        breadcrumb: 'Privacy Tools > About',
        url: null
    },
    privacy: {
        title: 'Why Privacy Matters',
        icon: '🔒',
        breadcrumb: 'Privacy Tools > Why Privacy Matters',
        url: null
    }
};

let currentTool = 'home';

// Switch to a tool (or internal screen) by name
function loadTool(toolName) {
    console.log('Loading tool:', toolName);

    if (!tools[toolName]) {
        console.error('Tool not found:', toolName);
        return;
    }

    currentTool = toolName;
    updateNavigation();
    updateHeader(toolName);

    if (toolName === 'home') {
        showScreen('welcome-content');
    } else if (toolName === 'about') {
        showScreen('about-content');
    } else if (toolName === 'privacy') {
        showScreen('privacy-content');
    } else {
        loadToolContent(toolName);
    }

    // Always close nav panel after selection (for mobile)
    toggleNav(false);
}

// Highlight the active item in the nav menu
function updateNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });

    const activeItem = document.querySelector(`[data-tool="${currentTool}"]`);
    if (activeItem) {
        activeItem.classList.add('active');
    }
}

// Update icon, title, breadcrumb and optional note in the header
function updateHeader(toolName) {
    const tool = tools[toolName];
    const iconEl = document.getElementById('content-icon');
    const titleEl = document.getElementById('content-title-text');
    const crumbEl = document.getElementById('breadcrumb');
    const noteEl = document.getElementById('tool-note');

    if (iconEl) iconEl.textContent = tool.icon;
    if (titleEl) titleEl.textContent = tool.title;
    if (crumbEl) crumbEl.textContent = tool.breadcrumb;

    // Show the note only if the tool defines one
    if (noteEl) {
        noteEl.textContent = tool.note || '';
        noteEl.classList.toggle('is-hidden', !tool.note);
        noteEl.classList.toggle('is-visible-block', Boolean(tool.note));
    }
}

// Hide every screen and the iframe
function hideAllScreens() {
    ['welcome-content', 'about-content', 'privacy-content'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.classList.add('is-hidden');
            el.classList.remove('is-visible-flex');
        }
    });

    const iframe = document.getElementById('content-frame');
    if (iframe) {
        iframe.classList.add('is-hidden');
        iframe.classList.remove('is-visible-block');
    }
}

// Show a specific internal screen
function showScreen(screenId) {
    hideAllScreens();
    const el = document.getElementById(screenId);
    if (el) {
        el.classList.remove('is-hidden');
        el.classList.add('is-visible-flex');
    }
}

// Load an external tool into the iframe
function loadToolContent(toolName) {
    const tool = tools[toolName];
    if (!tool.url) return;

    showLoading();
    hideAllScreens();

    const iframe = document.getElementById('content-frame');
    if (iframe) {
        iframe.classList.remove('is-hidden');
        iframe.classList.add('is-visible-block');
        iframe.src = tool.url;
    }
}

function showLoading() {
    const el = document.getElementById('loading-overlay');
    if (el) el.classList.add('show');
}

function hideLoading() {
    const el = document.getElementById('loading-overlay');
    if (el) el.classList.remove('show');
}

// Open/close the nav panel. No argument = toggle; true/false = force state
function toggleNav(show) {
    const navPanel = document.querySelector('.nav-panel');
    const navOverlay = document.querySelector('.nav-overlay');
    const navToggle = document.querySelector('.mobile-nav-toggle');

    if (!navPanel) return;

    const shouldShow = show === undefined
        ? !navPanel.classList.contains('open')
        : show;

    navPanel.classList.toggle('open', shouldShow);
    if (navOverlay) navOverlay.classList.toggle('show', shouldShow);
    if (navToggle) navToggle.classList.toggle('active', shouldShow);
}

document.addEventListener('DOMContentLoaded', function () {
    console.log('Dashboard loaded');

    // Nav menu clicks
    document.querySelectorAll('.nav-item').forEach(button => {
        button.addEventListener('click', function () {
            const toolName = button.getAttribute('data-tool');
            loadTool(toolName);
        });
    });

    // Tool preview cards (welcome screen)
    document.querySelectorAll('.tool-preview').forEach(preview => {
        preview.addEventListener('click', function () {
            const toolName = preview.getAttribute('data-tool');
            loadTool(toolName);
        });
    });

    // Mobile nav toggle button
    const navToggle = document.querySelector('.mobile-nav-toggle');
    if (navToggle) {
        navToggle.addEventListener('click', function () {
            toggleNav();
        });
    }

    // Overlay click closes nav
    const navOverlay = document.querySelector('.nav-overlay');
    if (navOverlay) {
        navOverlay.addEventListener('click', function () {
            toggleNav(false);
        });
    }

    // Iframe load — hide loading overlay
    const iframe = document.getElementById('content-frame');
    if (iframe) {
        iframe.addEventListener('load', function () {
            console.log('Iframe loaded');
            hideLoading();
            updateHeader(currentTool);
        });
    }

    // Start with welcome screen
    loadTool('home');
});
