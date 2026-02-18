// --- Copy Helper ---
const t = (k, f) => window.CtbI18n?.t(k, f) || f;
function copyOutput(elementId, btn) {
    const el = document.getElementById(elementId);
    let text = '';
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') text = el.value;
    else text = el.textContent;

    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
        const original = btn.innerHTML;
        btn.innerHTML = `<i class="fa-solid fa-check"></i> ${t('tool.common.copied', 'Copié')}`;
        setTimeout(() => btn.innerHTML = original, 1500);
    } catch (err) {
        console.error('Copy failed', err);
    }
    document.body.removeChild(textArea);
}

// --- Tab Management ---
function openTab(tabName) {
    // Hide all contents
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    // Deactivate all buttons
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    
    // Show selected
    document.getElementById(tabName).classList.add('active');
    // Activate button (find button that calls this function)
    const btns = document.querySelectorAll('.tab-btn');
    btns.forEach(btn => {
        if(btn.getAttribute('onclick').includes(tabName)) {
            btn.classList.add('active');
        }
    });
}

// --- Base64 ---
function processBase64(action) {
    const input = document.getElementById('b64Input').value;
    const output = document.getElementById('b64Output');
    try {
        if (action === 'encode') {
            // UTF-8 safe encoding
            output.value = btoa(unescape(encodeURIComponent(input)));
        } else {
            output.value = decodeURIComponent(escape(atob(input)));
        }
    } catch (e) {
        output.value = t('tool.encoder.err_base64', "Erreur : Entrée invalide pour Base64.");
    }
}

// --- JSON ---
function processJSON(action) {
    const input = document.getElementById('jsonInput').value;
    const output = document.getElementById('jsonOutput');
    try {
        const obj = JSON.parse(input);
        if (action === 'format') {
            output.value = JSON.stringify(obj, null, 4);
        } else {
            output.value = JSON.stringify(obj);
        }
    } catch (e) {
        output.value = t('tool.encoder.err_json', "Erreur : JSON invalide.") + "\n" + e.message;
    }
}

// --- URL ---
function processURL(action) {
    const input = document.getElementById('urlInput').value;
    const output = document.getElementById('urlOutput');
    try {
        if (action === 'encode') {
            output.value = encodeURIComponent(input);
        } else {
            output.value = decodeURIComponent(input);
        }
    } catch (e) {
        output.value = t('tool.encoder.err_url', "Erreur lors du traitement URL.");
    }
}

// --- Hash (SHA) ---
async function processHash(algo) {
    const input = document.getElementById('hashInput').value;
    const output = document.getElementById('hashOutput');
    
    if (!input) { output.textContent = t('tool.encoder.enter_text', "Veuillez entrer du texte."); return; }

    // Vérification : Web Crypto API (HTTPS) ou Fallback CryptoJS (HTTP)
    if (window.crypto && window.crypto.subtle) {
        const msgBuffer = new TextEncoder().encode(input);
        const hashBuffer = await crypto.subtle.digest(algo, msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        output.textContent = hashHex;
    } else if (typeof CryptoJS !== 'undefined') {
        let hash = (algo === 'SHA-256') ? CryptoJS.SHA256(input) : CryptoJS.SHA512(input);
        output.textContent = hash.toString(CryptoJS.enc.Hex);
    } else {
        output.textContent = t('tool.encoder.err_crypto', "Erreur : API Crypto non disponible (HTTPS requis ou librairie manquante).");
    }
}

// --- AES Encryption (Web Crypto API) ---
async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
}

async function processAES(action) {
    const text = document.getElementById('aesInput').value;
    const password = document.getElementById('aesKey').value;
    const output = document.getElementById('aesOutput');

    if (!password) { alert(t('tool.encoder.enter_key', "Veuillez entrer une clé/mot de passe.")); return; }
    if (!text) { alert(t('tool.encoder.enter_text', "Veuillez entrer du texte.")); return; }

    // Mode HTTPS (Web Crypto API - Plus sécurisé, format JSON)
    if (window.crypto && window.crypto.subtle) {
        try {
            if (action === 'encrypt') {
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const key = await deriveKey(password, salt);
                const enc = new TextEncoder();
                
                const encrypted = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv }, key, enc.encode(text)
                );

                const bufferToBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
                
                const result = {
                    salt: bufferToBase64(salt),
                    iv: bufferToBase64(iv),
                    data: bufferToBase64(encrypted)
                };
                
                output.value = JSON.stringify(result);
            } else {
                let obj;
                try { obj = JSON.parse(text); } catch(e) { throw new Error(t('tool.encoder.err_format_json', "Format invalide (attendu: JSON).")); }

                const base64ToBuffer = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0));
                const salt = base64ToBuffer(obj.salt);
                const iv = base64ToBuffer(obj.iv);
                const data = base64ToBuffer(obj.data);
                
                const key = await deriveKey(password, salt);
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv }, key, data
                );
                
                output.value = new TextDecoder().decode(decrypted);
            }
        } catch (e) {
            output.value = t('tool.encoder.err_webcrypto', "Erreur WebCrypto : ") + e.message;
        }
    } 
    // Mode HTTP (CryptoJS Fallback - Format String Base64 standard)
    else if (typeof CryptoJS !== 'undefined') {
        try {
            if (action === 'encrypt') {
                const encrypted = CryptoJS.AES.encrypt(text, password).toString();
                output.value = encrypted;
            } else {
                const decrypted = CryptoJS.AES.decrypt(text, password);
                const str = decrypted.toString(CryptoJS.enc.Utf8);
                if (!str) throw new Error(t('tool.encoder.err_bad_key', "Mauvaise clé ou données corrompues"));
                output.value = str;
            }
        } catch (e) {
            output.value = t('tool.encoder.err_cryptojs', "Erreur CryptoJS : ") + e.message;
        }
    } 
    else {
        output.value = t('tool.encoder.err_http_crypto', "Erreur : Contexte non sécurisé (HTTP) et librairie CryptoJS manquante.");
    }
}

// --- JWT Decoder ---
function processJWT() {
    const input = document.getElementById('jwtInput').value.trim();
    const output = document.getElementById('jwtOutput');
    
    if (!input) { output.value = ""; return; }

    const parts = input.split('.');
    if (parts.length !== 3) {
        output.value = t('tool.encoder.err_jwt', 'Error: Invalid JWT format (must contain 3 parts separated by dots).');
        return;
    }

    try {
        const decodePart = (str) => {
            // Base64Url to Base64
            let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
            // Padding
            while (base64.length % 4) base64 += '=';
            // Decode
            return JSON.parse(decodeURIComponent(escape(atob(base64))));
        };

        const header = decodePart(parts[0]);
        const payload = decodePart(parts[1]);

        output.value = "HEADER:\n" + JSON.stringify(header, null, 4) +
                       "\n\nPAYLOAD:\n" + JSON.stringify(payload, null, 4);
    } catch (e) {
        output.value = t('tool.encoder.err_decode', 'Error decoding') + ": " + e.message;
    }
}

// --- Timestamp Converter ---
function processTimestamp(action) {
    if (action === 'to_date') {
        const ts = parseInt(document.getElementById('tsInput').value);
        const out = document.getElementById('tsDateOutput');
        if (isNaN(ts)) { out.textContent = t('tool.encoder.invalid_ts', 'Invalid timestamp'); return; }
        
        // Gestion secondes vs millisecondes (si > année 3000, c'est probablement des ms)
        const date = new Date(ts > 100000000000 ? ts : ts * 1000);
        out.textContent = date.toLocaleString() + ` (ISO: ${date.toISOString()})`;
    } else {
        const dateVal = document.getElementById('dateInput').value;
        const out = document.getElementById('tsOutput');
        if (!dateVal) { out.textContent = t('tool.encoder.invalid_date', 'Invalid date'); return; }
        
        const date = new Date(dateVal);
        const ts = Math.floor(date.getTime() / 1000);
        out.textContent = ts;
        // Copie auto dans l'input du haut pour faciliter la conversion inverse
        document.getElementById('tsInput').value = ts;
    }
}

// --- CIDR Calculator ---
function processCIDR() {
    const input = document.getElementById('cidrInput').value.trim();
    const output = document.getElementById('cidrOutput');
    
    if (!input.match(/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/)) {
        output.value = t('tool.encoder.cidr_invalid', 'Invalid format. Use IP/Mask format (e.g. 192.168.1.1/24)');
        return;
    }

    const [ip, maskStr] = input.split('/');
    const maskBits = maskStr ? parseInt(maskStr) : 32;
    
    if (maskBits < 0 || maskBits > 32) { output.value = t('tool.encoder.cidr_mask_invalid', 'Invalid mask (0-32).'); return; }

    // IP to Long (Unsigned)
    const ipParts = ip.split('.').map(Number);
    if (ipParts.some(p => p < 0 || p > 255)) { output.value = t('tool.encoder.cidr_ip_invalid', 'Invalid IP (octets 0-255).'); return; }
    
    // Calculs binaires (avec >>> 0 pour gérer le non-signé en JS)
    const ipLong = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
    const maskLong = (maskBits === 0 ? 0 : (~0 << (32 - maskBits))) >>> 0;
    const netLong = (ipLong & maskLong) >>> 0;
    const broadLong = (netLong | (~maskLong)) >>> 0;
    
    const longToIp = (l) => [(l >>> 24) & 255, (l >>> 16) & 255, (l >>> 8) & 255, l & 255].join('.');

    const netIp = longToIp(netLong);
    const broadIp = longToIp(broadLong);
    const maskIp = longToIp(maskLong);
    
    // Hôtes
    const firstHost = (maskBits >= 31) ? 'N/A' : longToIp(netLong + 1);
    const lastHost = (maskBits >= 31) ? 'N/A' : longToIp(broadLong - 1);
    const totalHosts = (maskBits === 32) ? 1 : (maskBits === 31) ? 2 : Math.pow(2, 32 - maskBits) - 2;
    const totalIps = Math.pow(2, 32 - maskBits);

    output.value =
        `CIDR:          ${ip}/${maskBits}\n` +
        `${t('tool.encoder.cidr_mask', 'Mask')}:        ${maskIp}\n` +
        `${t('tool.encoder.cidr_network', 'Network')}:        ${netIp}\n` +
        `${t('tool.encoder.cidr_broadcast', 'Broadcast')}:     ${broadIp}\n` +
        `${t('tool.encoder.cidr_first_host', 'First Host')}:  ${firstHost}\n` +
        `${t('tool.encoder.cidr_last_host', 'Last Host')}:  ${lastHost}\n` +
        `${t('tool.encoder.cidr_usable_hosts', 'Usable Hosts')}:  ${totalHosts.toLocaleString()}\n` +
        `${t('tool.encoder.cidr_total_ips', 'Total IPs')}:     ${totalIps.toLocaleString()}`;
}

// --- User Agent Parser ---
function processUA() {
    const input = document.getElementById('uaInput').value.trim();
    const output = document.getElementById('uaOutput');
    
    if (!input) { output.value = ""; return; }

    if (typeof UAParser === 'undefined') {
        output.value = t('tool.encoder.err_ua', 'Error: UAParser library not loaded.');
        return;
    }

    const parser = new UAParser(input);
    const result = parser.getResult();

    output.value = `${t('tool.encoder.ua_browser', 'BROWSER')}:\n` + JSON.stringify(result.browser, null, 4) +
                   `\n\n${t('tool.encoder.ua_os', 'OS')}:\n` + JSON.stringify(result.os, null, 4) +
                   `\n\n${t('tool.encoder.ua_device', 'DEVICE')}:\n` + JSON.stringify(result.device, null, 4) +
                   `\n\n${t('tool.encoder.ua_engine', 'ENGINE')}:\n` + JSON.stringify(result.engine, null, 4);
}

// --- Markdown ---
function updateMarkdown() {
    const input = document.getElementById('mdInput').value;
    const output = document.getElementById('mdOutput');
    
    // Utilisation de la librairie 'marked' chargée via CDN
    if (typeof marked !== 'undefined') {
        output.innerHTML = marked.parse(input);
    } else {
        output.innerHTML = t('tool.encoder.err_marked', 'Error: Marked library not loaded.');
    }
}

// Init Markdown with default text
document.addEventListener('DOMContentLoaded', () => {
    if(document.getElementById('mdInput').value === '') {
        document.getElementById('mdInput').value = t('tool.encoder.md_default', '# Hello!\n\nThis is a real-time **Markdown** editor');
        updateMarkdown();
    }
});
