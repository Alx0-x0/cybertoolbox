// --- Copy Helper ---
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
        btn.innerHTML = '<i class="fa-solid fa-check"></i> Copié';
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
        output.value = "Erreur : Entrée invalide pour Base64.";
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
        output.value = "Erreur : JSON invalide.\n" + e.message;
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
        output.value = "Erreur lors du traitement URL.";
    }
}

// --- Hash (SHA) ---
async function processHash(algo) {
    const input = document.getElementById('hashInput').value;
    const output = document.getElementById('hashOutput');
    
    if (!input) { output.textContent = "Veuillez entrer du texte."; return; }

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
        output.textContent = "Erreur : API Crypto non disponible (HTTPS requis ou librairie manquante).";
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

    if (!password) { alert("Veuillez entrer une clé/mot de passe."); return; }
    if (!text) { alert("Veuillez entrer du texte."); return; }

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
                try { obj = JSON.parse(text); } catch(e) { throw new Error("Format invalide (attendu: JSON)."); }

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
            output.value = "Erreur WebCrypto : " + e.message;
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
                if (!str) throw new Error("Mauvaise clé ou données corrompues");
                output.value = str;
            }
        } catch (e) {
            output.value = "Erreur CryptoJS : " + e.message;
        }
    } 
    else {
        output.value = "Erreur : Contexte non sécurisé (HTTP) et librairie CryptoJS manquante.";
    }
}

// --- Markdown ---
function updateMarkdown() {
    const input = document.getElementById('mdInput').value;
    const output = document.getElementById('mdOutput');
    
    // Utilisation de la librairie 'marked' chargée via CDN
    if (typeof marked !== 'undefined') {
        output.innerHTML = marked.parse(input);
    } else {
        output.innerHTML = "Erreur : Librairie Marked non chargée.";
    }
}

// Init Markdown with default text
document.addEventListener('DOMContentLoaded', () => {
    if(document.getElementById('mdInput').value === '') {
        document.getElementById('mdInput').value = "# Bonjour !\n\nCeci est un éditeur **Markdown** en temps réel";
        updateMarkdown();
    }
});