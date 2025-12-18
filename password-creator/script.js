// --- Copy Helper ---
window.copyToClipboard = (text, btn) => {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
        if(btn) {
            const original = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-check"></i>';
            setTimeout(() => btn.innerHTML = original, 1500);
        }
    } catch (err) { console.error(err); }
    document.body.removeChild(textArea);
};

// --- Generator Logic ---
const chars = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    number: '0123456789',
    symbol: '!@#$%^&*()_+-=[]{}|;:,.<>?', // Default
    simpleSymbol: '!?@*$'
};

function generatePassword() {
    let length = parseInt(document.getElementById('lengthRange').value, 10);
    if (isNaN(length) || length < 1) length = 16;

    const useUpper = document.getElementById('useUpper').checked;
    const useNumbers = document.getElementById('useNumbers').checked;
    const useSymbols = document.getElementById('useSymbols').checked;
    const useSimpleSymbols = document.getElementById('useSimpleSymbols').checked;
    const excludeSimilar = document.getElementById('excludeSimilar').checked;
    const customSymbols = document.getElementById('customSymbols').value;

    let charset = chars.lower;
    if (useUpper) charset += chars.upper;
    if (useNumbers) charset += chars.number;
    if (useSimpleSymbols) charset += chars.simpleSymbol;
    if (useSymbols) charset += (customSymbols || chars.symbol);

    if (excludeSimilar) {
        charset = charset.replace(/[il1Lo0OI]/g, '');
    }

    if (charset.length === 0) return '';

    let password = '';
    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);

    for (let i = 0; i < length; i++) {
        password += charset[array[i] % charset.length];
    }

    // Garantie : Au moins un symbole si l'option est cochée
    const symbolsSelected = useSimpleSymbols || useSymbols;
    if (symbolsSelected) {
        const activeSymbols = (useSimpleSymbols ? chars.simpleSymbol : '') + 
                              (useSymbols ? (customSymbols || chars.symbol) : '');
        
        if (activeSymbols.length > 0) {
            const hasSymbol = [...password].some(c => activeSymbols.includes(c));
            if (!hasSymbol) {
                // Remplacement d'un caractère aléatoire par un symbole
                const randBuf = new Uint32Array(2);
                window.crypto.getRandomValues(randBuf);
                const pos = randBuf[0] % length;
                const symIndex = randBuf[1] % activeSymbols.length;
                password = password.substring(0, pos) + activeSymbols[symIndex] + password.substring(pos + 1);
            }
        }
    }

    return password;
}

function generateAndCheck() {
    const pwd = generatePassword();
    document.getElementById('generatedPassword').value = pwd;
    
    // Réinitialise le statut "non trouvé" lors de la génération d'un nouveau mot de passe
    document.getElementById('pwnedStatus').style.display = 'none';

    // Calcul de la force
    updateStrength(pwd);
    
    // Transfert automatique vers le vérificateur
    const checkInput = document.getElementById('checkInput');
    checkInput.value = pwd;
    
    // Lancement automatique de la vérification
    checkLeak();
}

function toggleComplexSymbols() {
    const cb = document.getElementById('useSymbols');
    const simpleCb = document.getElementById('useSimpleSymbols');
    const config = document.getElementById('symbolConfig');
    
    if (cb.checked) simpleCb.checked = false;
    
    if (cb.checked) config.classList.remove('disabled');
    else config.classList.add('disabled');
    savePreferences();
}

function toggleSimpleSymbols() {
    const simpleCb = document.getElementById('useSimpleSymbols');
    const complexCb = document.getElementById('useSymbols');
    if (simpleCb.checked) {
        complexCb.checked = false;
        toggleComplexSymbols(); // Met à jour l'UI des symboles complexes
    }
    savePreferences();
}

function updateStrength(password) {
    const meter = document.getElementById('strengthMeter');
    const bar = document.getElementById('strengthBarFill');
    const label = document.getElementById('strengthLabel');
    
    meter.style.display = 'block';
    
    // Analyse du contenu
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32; // Approx
    
    const length = password.length;
    const entropy = length * Math.log2(poolSize || 1);
    
    // UI Update
    let strength = 0; // 0-100
    let color = '#f85149'; // Red
    let text = 'Faible';
    
    if (entropy > 120) { strength = 100; color = '#3fb950'; text = 'Excellent'; }
    else if (entropy > 80) { strength = 75; color = '#00ff41'; text = 'Fort'; }
    else if (entropy > 50) { strength = 50; color = '#d29922'; text = 'Moyen'; }
    else { strength = 25; }
    
    bar.style.width = strength + '%';
    bar.style.backgroundColor = color;
    label.innerHTML = `Force: <span style="color:${color}">${text}</span> (${Math.round(entropy)} bits)`;
}

// --- Leak Checker Logic (SHA-1 + k-Anonymity) ---
async function sha1(str) {
    // Fallback CryptoJS pour HTTP
    if (typeof CryptoJS !== 'undefined') {
        return CryptoJS.SHA1(str).toString().toUpperCase();
    }
    // Web Crypto API (HTTPS only usually)
    if (window.crypto && window.crypto.subtle) {
        const enc = new TextEncoder();
        const hash = await crypto.subtle.digest('SHA-1', enc.encode(str));
        return Array.from(new Uint8Array(hash))
            .map(v => v.toString(16).padStart(2, '0'))
            .join('').toUpperCase();
    }
    return null;
}

async function checkLeak() {
    const password = document.getElementById('checkInput').value;
    const resultBox = document.getElementById('leakResult');
    const pwnedStatusSpan = document.getElementById('pwnedStatus');
    
    if (!password) return;

    resultBox.style.display = 'block';
    resultBox.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Vérification...';
    resultBox.className = 'result-box'; // Reset classes
    // Masque le statut à chaque nouvelle vérification
    pwnedStatusSpan.style.display = 'none';

    const hash = await sha1(password);
    if (!hash) {
        resultBox.textContent = "Erreur : Impossible de calculer le hash (Contexte non sécurisé ?)";
        return;
    }

    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);

    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const text = await response.text();
        
        // Recherche du suffixe dans la réponse
        const match = text.split('\n').find(line => line.startsWith(suffix));
        
        if (match) {
            const count = match.split(':')[1].trim();
            resultBox.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Ce mot de passe a été vu <strong>${parseInt(count).toLocaleString()}</strong> fois dans des fuites de données !`;
            resultBox.classList.add('danger');
        } else {
            resultBox.innerHTML = `<i class="fa-solid fa-shield-check"></i> Ce mot de passe n'a pas été trouvé dans la base de données publique.`;
            resultBox.classList.add('success');

            // Si le mot de passe vérifié est celui qui a été généré, on l'affiche à côté de la force
            const generatedPassword = document.getElementById('generatedPassword').value;
            if (password === generatedPassword) {
                pwnedStatusSpan.innerHTML = '<i class="fa-solid fa-shield-check"></i> Non trouvé';
                pwnedStatusSpan.style.display = 'inline';
            }
        }
    } catch (e) {
        resultBox.textContent = "Erreur de connexion à l'API.";
    }
}

// --- Persistence ---
function savePreferences() {
    const prefs = {
        length: document.getElementById('lengthRange').value,
        useUpper: document.getElementById('useUpper').checked,
        useNumbers: document.getElementById('useNumbers').checked,
        excludeSimilar: document.getElementById('excludeSimilar').checked,
        useSimpleSymbols: document.getElementById('useSimpleSymbols').checked,
        useSymbols: document.getElementById('useSymbols').checked,
        customSymbols: document.getElementById('customSymbols').value
    };
    localStorage.setItem('pwd_creator_prefs', JSON.stringify(prefs));
}

function loadPreferences() {
    const saved = localStorage.getItem('pwd_creator_prefs');
    if (saved) {
        const prefs = JSON.parse(saved);
        document.getElementById('lengthRange').value = prefs.length || 16;
        document.getElementById('lengthVal').textContent = prefs.length || 16;
        document.getElementById('useUpper').checked = prefs.useUpper;
        document.getElementById('useNumbers').checked = prefs.useNumbers;
        document.getElementById('excludeSimilar').checked = prefs.excludeSimilar;
        document.getElementById('useSimpleSymbols').checked = prefs.useSimpleSymbols;
        document.getElementById('useSymbols').checked = prefs.useSymbols;
        if (prefs.customSymbols) document.getElementById('customSymbols').value = prefs.customSymbols;
    }
    // Mise à jour de l'état visuel (désactivé/activé) des symboles complexes
    toggleComplexSymbols();
}

// Init
document.addEventListener('DOMContentLoaded', () => {
    // Charger les préférences ou utiliser les défauts (symboles décochés)
    loadPreferences();

    // Attacher la sauvegarde automatique aux inputs
    const inputs = document.querySelectorAll('input[type="checkbox"], input[type="range"], input[type="text"]');
    inputs.forEach(input => {
        if (input.id !== 'generatedPassword' && input.id !== 'checkInput') {
            input.addEventListener('change', savePreferences);
        }
    });

    // Générer un mot de passe au chargement (sans vérifier pour ne pas spammer)
    const pwd = generatePassword();
    document.getElementById('generatedPassword').value = pwd;
    updateStrength(pwd);

    // Validation avec la touche Entrée pour le vérificateur
    document.getElementById('checkInput').addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            checkLeak();
        }
    });
});