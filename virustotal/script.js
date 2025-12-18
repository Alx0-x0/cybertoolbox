let currentMode = 'file';
const API_URL_BASE = 'https://www.virustotal.com/api/v3';

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    const savedKey = localStorage.getItem('vt_api_key');
    if (savedKey) {
        document.getElementById('apiKeyInput').value = savedKey;
        updateApiStatus(true);
    } else {
        updateApiStatus(false);
        // Ouvrir le panneau si pas de clé
        document.getElementById('apiConfigPanel').style.display = 'block';
    }
    setMode('file');

    // --- Drag & Drop Events ---
    const dropZone = document.getElementById('dropZone');
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', handleDrop, false);
    
    // Click to upload simulation
    dropZone.addEventListener('click', () => {
        const input = document.createElement('input');
        input.type = 'file';
        input.onchange = e => {
            const file = e.target.files[0];
            if(file) processFile(file);
        };
        input.click();
    });
});

// --- UI Logic ---
function toggleApiConfig() {
    const panel = document.getElementById('apiConfigPanel');
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
}

function updateApiStatus(hasKey) {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    
    if (hasKey) {
        dot.className = 'status-dot active';
        text.textContent = 'API Connectée';
        text.style.color = 'var(--accent-color)';
    } else {
        dot.className = 'status-dot inactive';
        text.textContent = 'Clé API manquante';
        text.style.color = 'var(--danger)';
    }
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast';
    
    const icon = type === 'success' ? '<i class="fa-solid fa-check-circle" style="color:var(--accent-color)"></i>' : '<i class="fa-solid fa-circle-exclamation" style="color:var(--danger)"></i>';
    
    toast.innerHTML = `${icon} <span>${message}</span>`;
    container.appendChild(toast);

    // Auto remove
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function saveApiKey() {
    const key = document.getElementById('apiKeyInput').value.trim();
    if (key) {
        localStorage.setItem('vt_api_key', key);
        updateApiStatus(true);
        showToast('Clé API sauvegardée avec succès !');
        setTimeout(() => { document.getElementById('apiConfigPanel').style.display = 'none'; }, 1000);
    } else {
        localStorage.removeItem('vt_api_key');
        updateApiStatus(false);
        showToast('Clé API supprimée.', 'error');
    }
}

function setMode(mode) {
    currentMode = mode;
    
    // Update Tabs
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.querySelector(`.tab-btn[onclick="setMode('${mode}')"]`);
    if (activeBtn) activeBtn.classList.add('active');

    // Update Placeholder
    const input = document.getElementById('searchInput');
    const dropZone = document.getElementById('dropZone');

    if (mode === 'file') {
        input.placeholder = "Entrez le Hash (MD5, SHA-1, SHA-256)...";
        if (dropZone) dropZone.style.display = 'block';
    } else if (mode === 'url') {
        input.placeholder = "Entrez l'URL (ex: http://example.com)...";
        if (dropZone) dropZone.style.display = 'none';
    } else if (mode === 'domain') {
        input.placeholder = "Entrez le domaine (ex: google.com)...";
        if (dropZone) dropZone.style.display = 'none';
    } else if (mode === 'ip') {
        input.placeholder = "Entrez l'adresse IP (ex: 8.8.8.8)...";
        if (dropZone) dropZone.style.display = 'none';
    }
}

// --- File Hashing Logic ---
function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
}

async function processFile(file) {
    const dropZone = document.getElementById('dropZone');
    const originalText = dropZone.querySelector('p').textContent;
    dropZone.querySelector('p').textContent = "Calcul du Hash en cours...";
    
    try {
        const arrayBuffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        document.getElementById('searchInput').value = hashHex;
        showToast(`Hash calculé : ${hashHex.substring(0, 10)}...`);
        performScan();
    } catch (err) {
        console.error(err);
        showToast("Erreur lors du calcul du hash.", "error");
    } finally {
        dropZone.querySelector('p').textContent = originalText;
    }
}

// --- API Logic ---
async function performScan() {
    const apiKey = localStorage.getItem('vt_api_key');
    const inputVal = document.getElementById('searchInput').value.trim();
    const loader = document.getElementById('loader');
    const resultContainer = document.getElementById('resultContainer');
    const errorMsg = document.getElementById('errorMsg');

    if (!apiKey) {
        showToast("Veuillez d'abord configurer votre clé API.", 'error');
        document.getElementById('apiConfigPanel').style.display = 'block';
        return;
    }
    if (!inputVal) return;

    // Reset UI
    loader.style.display = 'block';
    resultContainer.style.display = 'none';
    errorMsg.style.display = 'none';

    try {
        let endpoint = '';
        let id = inputVal;

        // Note: Pour les URLs, il faut d'abord encoder en base64 sans padding
        if (currentMode === 'url') {
            const urlId = btoa(inputVal).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            endpoint = `/urls/${urlId}`;
        } else if (currentMode === 'file') {
            endpoint = `/files/${inputVal}`;
        } else if (currentMode === 'domain') {
            endpoint = `/domains/${inputVal}`;
        } else if (currentMode === 'ip') {
            endpoint = `/ip_addresses/${inputVal}`;
        }

        const response = await fetch(`${API_URL_BASE}${endpoint}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            if (response.status === 401) throw new Error("Clé API invalide.");
            if (response.status === 404) throw new Error("Ressource non trouvée sur VirusTotal (Jamais analysée ?).");
            if (response.status === 429) throw new Error("Quota API dépassé.");
            throw new Error(`Erreur API (${response.status})`);
        }

        const data = await response.json();
        displayResults(data.data);

    } catch (err) {
        console.error(err);
        errorMsg.textContent = err.message;
        errorMsg.style.display = 'block';
    } finally {
        loader.style.display = 'none';
    }
}

function displayResults(data) {
    const resultContainer = document.getElementById('resultContainer');
    const scoreBox = document.getElementById('scoreBox');
    const scoreCirclePath = document.getElementById('scoreCirclePath');
    const scoreText = document.getElementById('scoreText');
    const verdictText = document.getElementById('verdictText');
    const verdictSub = document.getElementById('verdictSub');
    const tagsContainer = document.getElementById('resTags');
    const mainInfoGrid = document.getElementById('mainInfoGrid');
    const detectionSection = document.getElementById('detectionSection');
    const detectionList = document.getElementById('detectionList');
    
    const attr = data.attributes;
    const stats = attr.last_analysis_stats;
    const malicious = stats.malicious;
    const total = stats.malicious + stats.harmless + stats.undetected + stats.suspicious;

    // Calculate Score & Animation
    const percentage = total > 0 ? Math.round((malicious / total) * 100) : 0;
    
    // Reset Styles
    scoreBox.className = 'vt-header-box';
    
    let color = 'var(--success)';
    if (malicious > 0) {
        if (malicious < 4) {
            color = 'var(--warning)';
            verdictText.textContent = "Suspect";
            verdictSub.textContent = `${malicious} moteurs de sécurité ont signalé cette ressource.`;
        } else {
            color = 'var(--danger)';
            verdictText.textContent = "Malveillant";
            verdictSub.textContent = `${malicious} moteurs de sécurité ont signalé cette ressource.`;
        }
    } else {
        verdictText.textContent = "Sûr (Clean)";
        verdictSub.textContent = "Aucun moteur de sécurité n'a signalé de menace.";
    }

    scoreBox.style.borderColor = color;
    verdictText.style.color = color;

    // Animate SVG
    scoreCirclePath.style.stroke = color;
    scoreText.style.fill = color;
    scoreText.textContent = `${malicious}/${total}`;
    
    // Petit délai pour laisser le CSS transition faire l'effet si ré-appelé
    setTimeout(() => {
        // stroke-dasharray: value, 100 (où 100 est la circonférence totale définie par le path)
        // Ici on veut afficher le ratio de détection. 
        // Si 0 malicious, on met un tout petit trait ou 0.
        // Pour l'effet visuel, on peut utiliser le pourcentage de dangerosité.
        const visualPercent = total > 0 ? (malicious / total) * 100 : 0;
        scoreCirclePath.setAttribute('stroke-dasharray', `${visualPercent}, 100`);
    }, 50);

    // Tags
    tagsContainer.innerHTML = '';
    if (attr.tags && attr.tags.length > 0) {
        attr.tags.forEach(tag => {
            const span = document.createElement('span');
            span.className = 'vt-tag';
            span.textContent = tag;
            tagsContainer.appendChild(span);
        });
    }

    // Info Grid Generation
    mainInfoGrid.innerHTML = '';
    const addInfo = (label, value) => {
        if (!value) return;
        mainInfoGrid.innerHTML += `
            <div class="vt-card-mini">
                <h4>${label}</h4>
                <span>${value}</span>
            </div>`;
    };

    const date = new Date(attr.last_analysis_date * 1000).toLocaleString();
    addInfo('Dernière Analyse', date);
    addInfo('Type', data.type);

    // Specific Data based on Type
    if (data.type === 'file') {
        addInfo('Taille', formatBytes(attr.size));
        addInfo('Nom (Suggestion)', attr.names ? attr.names[0] : attr.meaningful_name);
        addInfo('Type MIME', attr.type_description);
    } else if (data.type === 'url') {
        addInfo('URL', attr.url);
        addInfo('Titre Page', attr.title);
        addInfo('Serveur', attr.last_http_response_headers?.server || 'N/A');
    } else if (data.type === 'domain') {
        addInfo('Registrar', attr.registrar);
        addInfo('Création', attr.creation_date ? new Date(attr.creation_date * 1000).toLocaleDateString() : 'N/A');
        addInfo('Réputation', attr.reputation);
    } else if (data.type === 'ip_address') {
        addInfo('Pays', attr.country);
        addInfo('Réseau', attr.network);
        addInfo('AS Owner', attr.as_owner);
    }

    // Detections List
    detectionList.innerHTML = '';
    if (malicious > 0 && attr.last_analysis_results) {
        detectionSection.style.display = 'block';
        Object.entries(attr.last_analysis_results).forEach(([engine, result]) => {
            if (result.category === 'malicious') {
                detectionList.innerHTML += `
                    <div class="detection-item">
                        <span class="detection-engine">${engine}</span>
                        <span class="detection-name">${result.result}</span>
                    </div>`;
            }
        });
    } else {
        detectionSection.style.display = 'none';
    }

    // Link
    let link = `https://www.virustotal.com/gui/`;
    if (currentMode === 'file') link += `file/${data.id}`;
    else if (currentMode === 'url') link += `url/${data.id}`;
    else if (currentMode === 'domain') link += `domain/${data.id}`;
    else if (currentMode === 'ip') link += `ip-address/${data.id}`;
    
    document.getElementById('vtLink').href = link;

    resultContainer.style.display = 'block';
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}