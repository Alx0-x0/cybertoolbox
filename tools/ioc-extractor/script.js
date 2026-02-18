const input = document.getElementById('inputText');
const results = document.getElementById('results');
const stats = document.getElementById('stats');
window.CtbI18n?.init();
const t = (k, f) => window.CtbI18n?.t(k, f) || f;

const patterns = {
    ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    url: /\bhttps?:\/\/[^\s"'<>]+/gi,
    domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi,
    email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    md5: /\b[a-fA-F0-9]{32}\b/g,
    sha1: /\b[a-fA-F0-9]{40}\b/g,
    sha256: /\b[a-fA-F0-9]{64}\b/g,
    cve: /\bCVE-\d{4}-\d{4,7}\b/gi
};

function uniq(values) {
    return [...new Set(values.map((v) => v.trim()).filter(Boolean))];
}

function findAll(text, regex) {
    const matches = text.match(regex) || [];
    return uniq(matches);
}

function extractIocs(text) {
    const out = {
        ipv4: findAll(text, patterns.ipv4),
        url: findAll(text, patterns.url),
        email: findAll(text, patterns.email),
        md5: findAll(text, patterns.md5),
        sha1: findAll(text, patterns.sha1),
        sha256: findAll(text, patterns.sha256),
        cve: findAll(text, patterns.cve)
    };

    const domains = findAll(text, patterns.domain).filter((d) => !out.email.some((e) => e.endsWith(`@${d}`)));
    out.domain = uniq(domains.filter((d) => !out.url.some((u) => {
        try {
            return new URL(u).hostname.toLowerCase() === d.toLowerCase();
        } catch {
            return false;
        }
    })));

    return out;
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderStats(data) {
    const labels = {
        ipv4: 'IPv4',
        domain: 'Domain',
        url: 'URL',
        email: 'Email',
        md5: 'MD5',
        sha1: 'SHA1',
        sha256: 'SHA256',
        cve: 'CVE'
    };
    stats.innerHTML = Object.keys(labels).map((k) => `
        <div class="stat-card">
            <span class="k">${labels[k]}</span>
            <span class="v">${data[k].length}</span>
        </div>
    `).join('');
}

function renderResults(data) {
    const blocks = [
        ['ipv4', 'IP Addresses'],
        ['domain', 'Domains'],
        ['url', 'URLs'],
        ['email', 'Emails'],
        ['md5', 'MD5'],
        ['sha1', 'SHA1'],
        ['sha256', 'SHA256'],
        ['cve', 'CVEs']
    ];

    results.innerHTML = blocks.map(([k, title]) => `
        <div class="ioc-block">
            <div class="ioc-title">
                <h3>${title} (${data[k].length})</h3>
            </div>
            <div class="ioc-list">
                ${data[k].length ? data[k].map((v) => `
                    <div class="ioc-item">
                        <span>${escapeHtml(v)}</span>
                        <button type="button" data-copy="${escapeHtml(v)}"><i class="fa-regular fa-copy"></i></button>
                    </div>
                `).join('') : `<div class="ioc-item"><span>${t('tool.ioc.none', 'No result')}</span></div>`}
            </div>
        </div>
    `).join('');
}

function toFlatText(data) {
    return Object.entries(data)
        .map(([k, values]) => `${k.toUpperCase()}:\n${values.join('\n') || '-'}`)
        .join('\n\n');
}

function runExtraction() {
    const text = input.value.trim();
    const data = extractIocs(text);
    renderStats(data);
    renderResults(data);
    window.__iocData = data;
}
document.addEventListener('ctb:lang-change', () => {
    if (window.__iocData) {
        renderStats(window.__iocData);
        renderResults(window.__iocData);
    }
});

document.getElementById('extractBtn').addEventListener('click', runExtraction);

document.getElementById('sampleBtn').addEventListener('click', () => {
    input.value = [
        'Alert from EDR: CVE-2025-12345 exploited from 185.220.101.1',
        'Callback URL: https://evil-example.org/login.php?token=abc',
        'Domain: c2.bad-infra.net',
        'Hashes: d41d8cd98f00b204e9800998ecf8427e,',
        'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3,',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'Contact: attacker@bad-mail.cc'
    ].join('\n');
    runExtraction();
});

document.getElementById('clearBtn').addEventListener('click', () => {
    input.value = '';
    stats.innerHTML = '';
    results.innerHTML = '';
    window.__iocData = null;
});

document.getElementById('copyAllBtn').addEventListener('click', async () => {
    if (!window.__iocData) return;
    await navigator.clipboard.writeText(toFlatText(window.__iocData));
});

results.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    await navigator.clipboard.writeText(btn.dataset.copy);
});
