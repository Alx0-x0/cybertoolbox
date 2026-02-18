// --- Configuration ---
const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA'];

// --- DOM Elements ---
const form = document.getElementById('dnsForm');
const input = document.getElementById('domainInput');
const providerSelect = document.getElementById('providerSelect');
const dkimInput = document.getElementById('dkimSelector');
const historyContainer = document.getElementById('historyContainer');
const resultsContainer = document.getElementById('resultsContainer');
const loader = document.getElementById('loader');
const errorMsg = document.getElementById('errorMessage');
const parsedDomainLabel = document.getElementById('parsedDomain');
const t = (k, f) => window.CtbI18n?.t(k, f) || f;


// --- Helper Functions ---

/**
 * Fonction de copie compatible HTTP (Fallback)
 */
window.copyToClipboard = async (text, btn) => {
    const showFeedback = () => {
        if (btn) {
            const original = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-check" style="color:var(--success)"></i>';
            setTimeout(() => btn.innerHTML = original, 1500);
        }
    };

    // Modern API (HTTPS)
    if (navigator.clipboard?.writeText) {
        try {
            await navigator.clipboard.writeText(text);
            showFeedback();
            return;
        } catch (_) { /* fallback below */ }
    }

    // Fallback (HTTP) – preventScroll avoids jumping to top
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.top = "-9999px";
    document.body.appendChild(textArea);
    textArea.focus({ preventScroll: true });
    textArea.select();

    try {
        document.execCommand('copy');
        showFeedback();
    } catch (err) {
        console.error('Erreur copie', err);
        alert(t('tool.dns.copy_error', "Impossible de copier le texte."));
    }

    document.body.removeChild(textArea);
};

/**
 * Extrait le hostname propre d'une URL ou d'une chaîne brute.
 */
const extractHostname = (val) => {
    let url = val.trim();
    if (!url) return null;
    
    // Ajoute https:// si absent pour que l'objet URL fonctionne
    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
    }

    try {
        const hostname = new URL(url).hostname;
        return hostname;
    } catch (e) {
        return null;
    }
};

/**
 * Détermine la couleur de la bordure en fonction du type DNS
 */
const getTypeColor = (type) => {
    return `dns-type-${type.toLowerCase()}`;
};

/**
 * Crée le HTML pour une carte de résultat
 */
const createCard = (type, records, delay = 0) => {
    const typeClass = getTypeColor(type);
    
    let rows = '';
    if (records && records.length > 0) {
        rows = records.map(rec => {
            // Formatage spécial pour MX (Priorité + Serveur)
            let content = rec.data;
            if (type === 'MX') {
                const parts = rec.data.split(/\s+/);
                if (parts.length > 1) {
                    content = `<span style="color:var(--accent-color); font-weight:bold; margin-right:8px;" title="${t('tool.dns.priority', 'Priority')}">${parts[0]}</span><span>${parts.slice(1).join(' ')}</span>`;
                }
            }
            // Formatage spécial pour A (Placeholder Geo)
            if (type === 'A') {
                    content += `<span class="geo-ip" style="margin-left:8px; font-size:0.8em; color:var(--text-light);" data-ip="${rec.data}"></span>`;
            }
            return `
            <div class="record-row">
                <div class="record-content">${content}</div>
                <button onclick="copyToClipboard('${rec.data.replace(/'/g, "\\'")}', this)" class="copy-btn" title="Copier">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                </button>
                <div class="record-ttl">TTL: ${rec.TTL}s</div>
            </div>
        `}).join('');
    } else {
        rows = `<div style="color:var(--text-light); font-style:italic; padding:10px;">${t('tool.dns.no_records', 'Aucun enregistrement trouvé.')}</div>`;
    }

    return `
        <div class="dns-card ${typeClass}" style="animation-delay: ${delay}ms">
            <div class="dns-card-header">
                <h3>${type}</h3>
                <span class="record-ttl">
                    ${records ? records.length : 0} record(s)
                </span>
            </div>
            <div class="dns-card-body">
                ${rows}
            </div>
        </div>
    `;
};

/**
 * Analyse SPF, DMARC et DKIM
 */
const analyzeSecurity = (txtRecords, dmarcRecords, dkimRecords, dkimSelector) => {
    const report = [];

    // Helper pour nettoyer les guillemets de Cloudflare (et autres)
    const cleanTXT = (data) => {
        if (typeof data === 'string' && data.startsWith('"') && data.endsWith('"')) {
            return data.slice(1, -1).replace(/\\"/g, '"');
        }
        return data;
    };

    // --- Helpers de parsing ---
    const parseSPF = (txt) => {
        const parts = txt.split(' ');
        return parts.map(part => {
            if (part.startsWith('v=spf1')) return null;
            if (part.startsWith('include:')) return { label: 'Include', val: part.split(':')[1], info: t('tool.dns.include', 'Authorized third-party domain') };
            if (part.startsWith('ip4:')) return { label: 'IPv4', val: part.split(':')[1], info: t('tool.dns.ip_authorized', 'Authorized IP') };
            if (part.startsWith('ip6:')) return { label: 'IPv6', val: part.split(':')[1], info: t('tool.dns.ip_authorized', 'Authorized IP') };
            if (part === 'a') return { label: 'A', val: 'A Record', info: t('tool.dns.a_record', 'Domain IP authorized') };
            if (part === 'mx') return { label: 'MX', val: 'MX Record', info: t('tool.dns.mx_authorized', 'Authorized mail servers') };
            if (part.endsWith('all')) {
                const q = part.slice(0, -3);
                const map = { '-': t('tool.dns.spf_strict', 'Strict (Fail)'), '~': t('tool.dns.spf_softfail', 'Soft (SoftFail)'), '?': t('tool.dns.spf_neutral', 'Neutral'), '+': t('tool.dns.spf_permissive', 'Permissive') };
                return { label: t('tool.dns.policy', 'Policy'), val: part, info: map[q] || t('tool.header.unknown_status', 'Unknown') };
            }
            return { label: 'Other', val: part, info: '' };
        }).filter(x => x);
    };

    const parseDMARC = (txt) => {
        return txt.split(';').map(p => p.trim()).filter(p => p && !p.startsWith('v=DMARC1')).map(part => {
            const [k, ...vParts] = part.split('=');
            const v = vParts.join('=');
            if (k === 'p') {
                const map = { 'none': t('tool.dns.dmarc_observation', 'Observation'), 'quarantine': t('tool.dns.dmarc_quarantine', 'Quarantine'), 'reject': t('tool.dns.dmarc_reject', 'Strict Reject') };
                return { label: `${t('tool.dns.policy', 'Policy')} (p)`, val: v, info: map[v] || '' };
            }
            if (k === 'rua') return { label: 'Reports (rua)', val: v, info: t('tool.dns.aggregate_reports', 'Aggregate report recipient') };
            if (k === 'ruf') return { label: 'Forensic (ruf)', val: v, info: t('tool.dns.forensic_reports', 'Failure report recipient') };
            if (k === 'pct') return { label: '%', val: v + '%', info: t('tool.dns.percentage', 'Application rate') };
            if (k === 'sp') return { label: 'Subdomains', val: v, info: t('tool.dns.subdomains', 'Specific policy') };
            return { label: k, val: v, info: '' };
        });
    };

    // 1. SPF Analysis
    const spfRecord = txtRecords ? txtRecords.find(r => cleanTXT(r.data).startsWith('v=spf1')) : null;
    if (spfRecord) {
        const data = cleanTXT(spfRecord.data);
        let status = 'status-success';
        let msg = t('tool.dns.valid', 'Valid');
        if (data.includes('-all')) msg += ' (Strict)';
        else if (data.includes('~all')) { msg += ' (SoftFail)'; status = 'status-warning'; }
        else if (data.includes('?all')) { msg += ' (Neutral)'; status = 'status-warning'; }
        else if (data.includes('+all')) { msg += ' (Permissive - Danger)'; status = 'status-danger'; }

        report.push({ name: 'SPF', status, msg, data: data, details: parseSPF(data) });
    } else {
        report.push({ name: 'SPF', status: 'status-danger', msg: t('tool.dns.missing', 'Missing'), data: t('tool.dns.no_spf', 'No v=spf1 record found.'), details: [] });
    }

    // 2. DMARC Analysis
    const dmarcRecord = dmarcRecords && dmarcRecords.length > 0 ? dmarcRecords[0] : null;
    if (dmarcRecord && cleanTXT(dmarcRecord.data).startsWith('v=DMARC1')) {
        const data = cleanTXT(dmarcRecord.data);
        let status = 'status-success';
        let msg = t('tool.dns.valid', 'Valid');
        if (data.includes('p=reject')) msg += ' (Reject)';
        else if (data.includes('p=quarantine')) { msg += ' (Quarantine)'; status = 'status-warning'; }
        else if (data.includes('p=none')) { msg += ` (None - ${t('tool.dns.dmarc_observation', 'Observation')})`; status = 'status-warning'; }

        report.push({ name: 'DMARC', status, msg, data: data, details: parseDMARC(data) });
    } else {
        report.push({ name: 'DMARC', status: 'status-danger', msg: t('tool.dns.missing', 'Missing'), data: t('tool.dns.no_dmarc', 'No _dmarc record found.'), details: [] });
    }

    // 3. DKIM Analysis (si sélecteur fourni)
    if (dkimSelector) {
        const dkimRecord = dkimRecords && dkimRecords.length > 0 ? dkimRecords[0] : null;
        if (dkimRecord && cleanTXT(dkimRecord.data).includes('v=DKIM1')) {
            const data = cleanTXT(dkimRecord.data);
            // Parsing simple pour DKIM
            const parts = data.split(';').map(p => p.trim()).filter(p => p && !p.startsWith('v=DKIM1'));
            const details = parts.map(part => {
                const [k, ...vParts] = part.split('=');
                const v = vParts.join('=');
                if (k === 'k') return { label: t('tool.dns.key_type', 'Key type'), val: v, info: '' };
                if (k === 'p') return { label: t('tool.dns.public_key', 'Public key'), val: t('tool.dns.present', 'Present'), info: t('tool.dns.crypto_key', 'Cryptographic key') };
                return { label: k, val: v, info: '' };
            });
            report.push({ name: `DKIM (${dkimSelector})`, status: 'status-success', msg: t('tool.dns.valid', 'Valid'), data: data, details: details });
        } else if (dkimRecord) {
                report.push({ name: `DKIM (${dkimSelector})`, status: 'status-warning', msg: t('tool.dns.uncertain_format', 'Uncertain format'), data: cleanTXT(dkimRecord.data), details: [] });
        } else {
            report.push({ name: `DKIM (${dkimSelector})`, status: 'status-danger', msg: t('tool.dns.missing', 'Missing'), data: `${t('tool.dns.not_found_for', 'No record for')} ${dkimSelector}._domainkey`, details: [] });
        }
    }

    return `
        <div class="dns-card dns-security" style="grid-column: 1 / -1;">
            <div class="dns-card-header">
                <h3 style="display:flex; align-items:center; gap:10px;">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    ${t('tool.dns.security_title', 'Security & Deliverability')}
                </h3>
                <span class="record-ttl">
                    ${report.length} ${t('tool.dns.protocols', 'protocols')}
                </span>
            </div>
            <div class="dns-card-body">
                ${report.map(item => {
                    let icon = '';
                    let titleColor = '';
                    let borderColor = '';

                    if (item.status.includes('success')) {
                        icon = '<svg style="width:20px; color:var(--success);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
                        titleColor = 'var(--success)';
                        borderColor = 'var(--success)';
                    } else if (item.status.includes('warning')) {
                        icon = '<svg style="width:20px; color:var(--warning);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>';
                        titleColor = 'var(--warning)';
                        borderColor = 'var(--warning)';
                    } else {
                        icon = '<svg style="width:20px; color:var(--danger);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
                        titleColor = 'var(--danger)';
                        borderColor = 'var(--danger)';
                    }

                    return `
                    <details class="group">
                        <summary class="sec-summary" style="border-left: 3px solid ${borderColor};">
                            <div style="display:flex; align-items:center; gap:10px;">
                                ${icon}
                                <span style="font-weight:bold; color:${titleColor};">${item.name}</span>
                                <span class="${item.status}">${item.msg}</span>
                            </div>
                            <div style="display:flex; align-items:center; gap:5px;">
                                <span style="font-size:0.8em; color:var(--text-light);">${t('tool.dns.details_label', 'Details')}</span>
                                <svg style="width:16px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                            </div>
                        </summary>
                        <div class="sec-details-panel">
                            <div style="position:relative; padding:10px; background:rgba(0,0,0,0.2); border-radius:4px; font-family:monospace; word-break:break-all;">
                                ${item.data}
                                <button onclick="copyToClipboard('${item.data.replace(/'/g, "\\'")}', this)" class="copy-btn" style="position:absolute; top:5px; right:5px;" title="Copier">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                                </button>
                            </div>
                            
                            ${item.details && item.details.length > 0 ? `
                                <div class="sec-grid">
                                    ${item.details.map(d => `
                                        <div class="sec-item">
                                            <span class="sec-label">${d.label}</span>
                                            <span class="sec-val" title="${d.val}">${d.val}</span>
                                            ${d.info ? `<div style="font-size:0.7em; opacity:0.7; margin-top:2px;">${d.info}</div>` : ''}
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}
                        </div>
                    </details>
                `}).join('')}
            </div>
        </div>
    `;
};

/**
 * Récupère les infos géographiques pour les IPs
 */
const getFlagEmoji = (countryCode) => {
    if (!countryCode) return '';
    return countryCode.toUpperCase().replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397));
};

const enrichIPs = async () => {
    const elements = document.querySelectorAll('.geo-ip');
    const ipsToFetch = new Set();
    elements.forEach(el => { if (!el.textContent) ipsToFetch.add(el.getAttribute('data-ip')); });

    for (const ip of ipsToFetch) {
        try {
            const res = await fetch(`https://get.geojs.io/v1/ip/geo/${ip}.json`);
            const data = await res.json();
            const flag = getFlagEmoji(data.country_code);
            const text = `${flag} ${data.country} ${data.city ? ' - ' + data.city : ''}`;
            
            document.querySelectorAll(`.geo-ip[data-ip="${ip}"]`).forEach(el => {
                el.textContent = text;
                el.style.color = 'var(--accent-color)';
                el.style.fontWeight = 'bold';
            });
        } catch (e) { console.error('Geo error', e); }
    }
};

// --- History & Export Logic ---

const loadHistory = () => {
    const history = JSON.parse(localStorage.getItem('dns_history') || '[]');
    if (history.length === 0) {
        historyContainer.innerHTML = '';
        return;
    }
    historyContainer.innerHTML = `<span class="text-text-light text-xs mr-2">${t('tool.dns.recent', 'Récents :')}</span>` + 
        history.map(h => `
            <div class="history-tag">
                <button onclick="window.setInputAndSearch('${h}')" class="history-btn">${h}</button>
                <button onclick="window.removeFromHistory('${h}')" class="history-remove" title="Supprimer">
                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
        `).join('');
};

const addToHistory = (domain) => {
    let history = JSON.parse(localStorage.getItem('dns_history') || '[]');
    history = history.filter(h => h !== domain); // Évite les doublons
    history.unshift(domain);
    if (history.length > 5) history.pop();
    localStorage.setItem('dns_history', JSON.stringify(history));
    loadHistory();
};

window.removeFromHistory = (domain) => {
    let history = JSON.parse(localStorage.getItem('dns_history') || '[]');
    history = history.filter(h => h !== domain);
    localStorage.setItem('dns_history', JSON.stringify(history));
    loadHistory();
};

// Fonction globale pour le onclick de l'historique
window.setInputAndSearch = (domain) => {
    input.value = domain;
    form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
};

// Init History
loadHistory();

// --- Auto-refresh on Provider Change ---
providerSelect.addEventListener('change', () => {
    if (input.value.trim()) {
        // Feedback visuel (Animation)
        providerSelect.classList.add('pulse-input');
        setTimeout(() => providerSelect.classList.remove('pulse-input'), 600);
        
        // Relance l'analyse automatiquement
        form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    }
});

// --- Main Logic ---

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // 1. Reset UI
    errorMsg.style.display = 'none';
    resultsContainer.innerHTML = '';
    resultsContainer.style.display = 'none';
    parsedDomainLabel.style.display = 'none';
    
    // 2. Validation
    const rawInput = input.value;
    const domain = extractHostname(rawInput);
    const dkimSelector = dkimInput.value.trim();

    if (!domain) {
        showError(t('tool.dns.invalid_domain', 'Invalid domain name. Please enter a valid URL or domain (e.g. google.com).'));
        return;
    }

    // Afficher le domaine interprété
    parsedDomainLabel.querySelector('span').textContent = domain;
    parsedDomainLabel.style.display = 'block';

    // Sauvegarde historique
    addToHistory(domain);

    // 3. Loading
    loader.style.display = 'block';

    // Configuration Provider
    const provider = providerSelect.value;
    const apiBase = provider === 'cloudflare' ? 'https://cloudflare-dns.com/dns-query' : 'https://dns.google/resolve';
    const headers = { 'Accept': 'application/dns-json' }; // Requis pour Cloudflare, fonctionne pour Google

    try {
        // 4. Fetch Data (Parallel Requests)
        // On lance toutes les requêtes en même temps pour la performance
        const standardPromises = RECORD_TYPES.map(type => 
            fetch(`${apiBase}?name=${domain}&type=${type}`, { headers })
                .then(res => {
                    if (!res.ok) throw new Error(`Erreur API (${res.status})`);
                    return res.json();
                })
                .then(data => ({ type, data }))
        );

        // Requêtes Spécifiques Sécurité
        const dmarcPromise = fetch(`${apiBase}?name=_dmarc.${domain}&type=TXT`, { headers }).then(r => r.json());
        
        let dkimPromise = Promise.resolve({});
        if (dkimSelector) {
            dkimPromise = fetch(`${apiBase}?name=${dkimSelector}._domainkey.${domain}&type=TXT`, { headers }).then(r => r.json());
        }

        const [results, dmarcData, dkimData] = await Promise.all([
            Promise.all(standardPromises),
            dmarcPromise,
            dkimPromise
        ]);


        // 5. Render Results
        let hasAnyResult = false;

        // --- Security Card ---
        // On récupère les TXT du domaine principal pour SPF
        const txtResult = results.find(r => r.type === 'TXT');
        const txtRecords = (txtResult && txtResult.data.Status === 0) ? txtResult.data.Answer : [];
        
        const dmarcRecords = (dmarcData.Status === 0 && dmarcData.Answer) ? dmarcData.Answer : [];
        const dkimRecords = (dkimData.Status === 0 && dkimData.Answer) ? dkimData.Answer : [];

        const securityHTML = analyzeSecurity(txtRecords, dmarcRecords, dkimRecords, dkimSelector);
        resultsContainer.insertAdjacentHTML('beforeend', securityHTML);

        // --- Standard Cards ---
        results.forEach(({ type, data }, index) => {
            // L'API Google renvoie 'Answer' si des résultats existent
            // Si Status !== 0, il y a une erreur DNS (ex: NXDOMAIN)
            const records = (data.Status === 0 && data.Answer) ? data.Answer : [];
            
            if (records.length > 0) hasAnyResult = true;
            
            // On affiche la carte même si vide, pour montrer qu'on a cherché
            const cardHTML = createCard(type, records, (index + 1) * 100);
            resultsContainer.insertAdjacentHTML('beforeend', cardHTML);
        });

        if (!hasAnyResult) {
            // Vérifier si le domaine existe vraiment (basé sur le Status de la première requête)
            const firstStatus = results[0].data.Status;
            if (firstStatus === 3) {
                showError(`${t('tool.dns.domain_label', 'The domain')} "${domain}" ${t('tool.dns.nxdomain', 'does not exist (NXDOMAIN).')}`);
                resultsContainer.innerHTML = ''; // On vide les cartes vides
            } 
        }

        loader.style.display = 'none';
        if (resultsContainer.innerHTML !== '') {
            resultsContainer.style.display = 'grid';
            // Enrichissement GeoIP
            enrichIPs();
            // Update URL pour partage
            const url = new URL(window.location);
            url.searchParams.set('domain', domain);
            window.history.pushState({}, '', url);
        }

    } catch (err) {
        loader.style.display = 'none';
        showError(t('tool.dns.technical_error', 'A technical error occurred while connecting to the DNS API.'));
        console.error(err);
    }
});

function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.style.display = 'block';
}

// Check URL params au chargement
const urlParams = new URLSearchParams(window.location.search);
const domainParam = urlParams.get('domain');
if (domainParam) {
    window.setInputAndSearch(domainParam);
}
