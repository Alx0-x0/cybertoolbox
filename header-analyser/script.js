// --- Copy Helper (HTTP Compatible) ---
window.copyToClipboard = (text, btn) => {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
        if (btn) {
            const original = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-check" style="color:var(--success)"></i>';
            setTimeout(() => btn.innerHTML = original, 1500);
        }
    } catch (err) {
        console.error('Copy failed', err);
    }
    document.body.removeChild(textArea);
};

// --- Drag & Drop Logic ---
const dropZone = document.getElementById('inputSection');
const inputArea = document.getElementById('headerInput');

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => dropZone.classList.add('drag-over'), false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => dropZone.classList.remove('drag-over'), false);
});

dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
        const reader = new FileReader();
        reader.onload = (e) => { inputArea.value = e.target.result; analyzeHeaders(); };
        reader.readAsText(files[0]);
    }
}, false);


// --- Analysis Logic ---
function analyzeHeaders() {
    const raw = document.getElementById('headerInput').value.trim();
    if (!raw) return alert("Veuillez coller un header d'abord.");

    // 1. Parse Headers
    const headers = parseRawHeaders(raw);
    
    // 2. Analyze Security (Deep)
    const security = analyzeSecurity(headers);

    // 3. Extract Key Info
    const info = {
        subject: getHeader(headers, 'Subject'),
        from: getHeader(headers, 'From'),
        replyTo: getHeader(headers, 'Reply-To'),
        to: getHeader(headers, 'To'),
        date: getHeader(headers, 'Date'),
        messageId: getHeader(headers, 'Message-ID'),
        contentType: getHeader(headers, 'Content-Type'),
        contentDisposition: getHeader(headers, 'Content-Disposition'),
        mailer: getHeader(headers, 'X-Mailer') || getHeader(headers, 'User-Agent'),
        listUnsubscribe: getHeader(headers, 'List-Unsubscribe'),
        priority: getHeader(headers, 'X-Priority'),
        spamStatus: getHeader(headers, 'X-Spam-Status'),
        returnPath: getHeader(headers, 'Return-Path'),
        spf: security.spf,
        dkim: security.dkim,
        dmarc: security.dmarc,
        dmarcPolicy: security.dmarcPolicy
    };

    // 4. Calculate Risk Score
    const riskData = calculateRisk(info);

    // 5. Parse Hops
    const hops = parseHops(headers);

    // 6. Render
    renderResults(info, riskData, raw, hops, headers);
}

function resetAnalysis() {
    document.getElementById('headerInput').value = '';
    document.getElementById('inputSection').style.display = 'block';
    document.getElementById('navActions').style.display = 'none';
    document.getElementById('results').style.display = 'none';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function parseRawHeaders(raw) {
    const lines = raw.split(/\r\n|\r|\n/);
    const headers = {};
    let currentKey = null;

    lines.forEach(line => {
        if (/^\s/.test(line) && currentKey) {
            // Folded line (continuation)
            if (Array.isArray(headers[currentKey])) {
                headers[currentKey][headers[currentKey].length - 1] += ' ' + line.trim();
            } else {
                headers[currentKey] += ' ' + line.trim();
            }
        } else {
            const match = line.match(/^([^:]+?)\s*:(.*)$/);
            if (match) {
                currentKey = match[1].trim().toLowerCase();
                const value = match[2].trim();
                if (headers[currentKey]) {
                    // Handle multiple headers with same name (like Received)
                    if (Array.isArray(headers[currentKey])) {
                        headers[currentKey].push(value);
                    } else {
                        headers[currentKey] = [headers[currentKey], value];
                    }
                } else {
                    headers[currentKey] = value;
                }
            }
        }
    });
    return headers;
}

function getHeader(headers, key) {
    const val = headers[key.toLowerCase()];
    let result = Array.isArray(val) ? val[0] : (val || 'Non trouvé');
    if (result !== 'Non trouvé') {
        result = decodeHeaderValue(result);
    }
    return result;
}

function decodeHeaderValue(val) {
    if (!val) return val;
    // Decode MIME encoded words (=?utf-8?B?...)
    return val.replace(/=\?([\w-]+)\?([BQ])\?([^\?]+)\?=/gi, (match, charset, encoding, text) => {
        try {
            if (encoding.toUpperCase() === 'B') {
                return new TextDecoder(charset).decode(Uint8Array.from(atob(text), c => c.charCodeAt(0)));
            } else if (encoding.toUpperCase() === 'Q') {
                return decodeURIComponent(text.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/g, '%$1'));
            }
        } catch (e) {
            return match;
        }
        return match;
    });
} 

function analyzeSecurity(headers) {
    // Helper to get all values as array, even if single string
    const getValues = (k) => {
        const v = headers[k];
        if (!v) return [];
        return Array.isArray(v) ? v : [v];
    };

    const authResults = getValues('authentication-results');
    const receivedSpf = getValues('received-spf');
    const dkimSig = headers['dkim-signature'];

    let spf = { status: 'Inconnu', details: 'Non trouvé' };
    let dkim = { status: 'Inconnu', details: 'Non trouvé' };
    let dmarc = { status: 'Inconnu', details: 'Non trouvé' };
    let dmarcPolicy = null;

    // Helper to extract status from Auth-Results string
    const extractStatus = (str, type) => {
        // Regex looks for "type=status" with optional spaces
        // \b ensures we don't match "aspf=" as "spf="
        const regex = new RegExp(`\\b${type}\\s*=\\s*([a-zA-Z]+)`, 'i');
        const match = str.match(regex);
        return match ? match[1].toUpperCase() : null;
    };

    // --- SPF ---
    // Priority 1: Received-SPF header (usually most specific)
    if (receivedSpf.length > 0) {
        // Take the first one (top-most)
        const val = receivedSpf[0];
        const lower = val.toLowerCase();
        
        if (lower.startsWith('pass')) spf.status = 'PASS';
        else if (lower.startsWith('fail')) spf.status = 'FAIL';
        else if (lower.startsWith('softfail')) spf.status = 'SOFTFAIL';
        else if (lower.startsWith('neutral')) spf.status = 'NEUTRAL';
        else if (lower.startsWith('none')) spf.status = 'NONE';
        else if (lower.startsWith('permerror')) spf.status = 'PERMERROR';
        else if (lower.startsWith('temperror')) spf.status = 'TEMPERROR';
        
        spf.details = val;
    } 
    
    // Priority 2: Authentication-Results (if SPF not found or to augment)
    if (spf.status === 'Inconnu' && authResults.length > 0) {
        for (const res of authResults) {
            const status = extractStatus(res, 'spf');
            if (status) {
                spf.status = status;
                const parts = res.split(';');
                const part = parts.find(p => /spf\s*=/i.test(p));
                spf.details = part ? part.trim() : res;
                break; 
            }
        }
    }

    // --- DKIM ---
    if (authResults.length > 0) {
        for (const res of authResults) {
            const status = extractStatus(res, 'dkim');
            if (status) {
                dkim.status = status;
                const parts = res.split(';');
                const part = parts.find(p => /dkim\s*=/i.test(p));
                dkim.details = part ? part.trim() : '';
                break;
            }
        }
    }
    
    if (dkimSig) {
        const sigs = Array.isArray(dkimSig) ? dkimSig : [dkimSig];
        const domains = sigs.map(s => {
            const d = s.match(/d=([^;]+)/);
            const sel = s.match(/s=([^;]+)/);
            return (d ? d[1].trim() : '?') + (sel ? ` (s=${sel[1].trim()})` : '');
        });
        
        if (dkim.details === 'Non trouvé') {
             dkim.details = 'Signature présente (Statut non vérifié)';
        }
        dkim.details += (dkim.details ? '<br>' : '') + '<strong>Signatures:</strong> ' + domains.join(', ');
    }

    // --- DMARC ---
    if (authResults.length > 0) {
        for (const res of authResults) {
            const status = extractStatus(res, 'dmarc');
            if (status) {
                dmarc.status = status;
                const parts = res.split(';');
                const part = parts.find(p => /dmarc\s*=/i.test(p));
                dmarc.details = part ? part.trim() : res;

                const policyMatch = res.match(/\bp\s*=\s*([a-z]+)/i);
                if (policyMatch) dmarcPolicy = policyMatch[1].toLowerCase();
                
                break;
            }
        }
    }

    return { spf, dkim, dmarc, dmarcPolicy };
}

function calculateRisk(info) {
    let score = 0; // 0 = Safe, 100 = Critical
    let reasons = [];

    const extractEmail = (str) => str?.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/)?.[1]?.toLowerCase();
    const fromEmail = extractEmail(info.from);
    const replyToEmail = extractEmail(info.replyTo);
    const returnPathEmail = extractEmail(info.returnPath);

    // SPF Check
    if (info.spf.status === 'FAIL') { score += 50; reasons.push({text: "SPF Échoué (Authentification serveur invalide)", score: 50, explanation: "L'adresse IP de l'expéditeur n'est pas autorisée à envoyer des emails pour ce domaine."}); }
    else if (info.spf.status === 'SOFTFAIL') { score += 25; reasons.push({text: "SPF Softfail (Authentification serveur partielle)", score: 25, explanation: "L'adresse IP de l'expéditeur n'est pas explicitement autorisée, mais n'est pas strictement interdite."}); }
    else if (info.spf.status === 'Inconnu') { score += 10; reasons.push({text: "SPF introuvable", score: 10, explanation: "Aucun enregistrement SPF trouvé pour ce domaine."}); }

    // DKIM Check
    if (info.dkim.status === 'FAIL') { score += 40; reasons.push({text: "DKIM Échoué (Signature cryptographique invalide)", score: 40, explanation: "La signature cryptographique du message est invalide ou a été altérée."}); }
    else if (info.dkim.status === 'Inconnu') { score += 10; reasons.push({text: "DKIM introuvable", score: 10, explanation: "Le message n'est pas signé cryptographiquement."}); }

    // DMARC Check
    if (info.dmarc.status === 'FAIL') { score += 40; reasons.push({text: "DMARC Échoué (Politique de sécurité non respectée)", score: 40, explanation: "Le message échoue aux vérifications SPF et/ou DKIM selon la politique du domaine."}); }

    // DMARC Policy Weakness (p=none)
    if (info.dmarc.status === 'PASS' && info.dmarcPolicy === 'none') {
        score += 10;
        reasons.push({text: "Politique DMARC permissive (p=none détecté)", score: 10, explanation: "Le domaine surveille mais ne bloque pas les emails frauduleux."});
    }

    // Reply-To Mismatch (High Risk Indicator for Phishing)
    if (fromEmail && replyToEmail && fromEmail !== replyToEmail) {
        score += 30;
        reasons.push({text: "Adresse de réponse différente de l'expéditeur", score: 30, explanation: "L'adresse de réponse est différente de l'adresse d'envoi, technique courante de phishing."});
    }

    // Return Path mismatch
    if (fromEmail && returnPathEmail) {
        const fromDomain = fromEmail.split('@')[1];
        const returnDomain = returnPathEmail.split('@')[1];
        // Allow subdomains or parent domains
        if (!returnDomain.includes(fromDomain) && !fromDomain.includes(returnDomain)) {
            score += 20;
            reasons.push({text: "Chemin de retour (Return-Path) incohérent", score: 20, explanation: "L'adresse de retour technique ne correspond pas au domaine de l'expéditeur."});
        }
    }

    // Suspicious Keywords in Subject (Nuanced)
    const highRiskKeywords = ['urgent', 'vérifiez', 'verify', 'suspendu', 'suspended', 'immédiat', 'action requise', 'securite', 'security'];
    const mediumRiskKeywords = ['account', 'compte', 'banque', 'facture', 'invoice', 'mot de passe', 'password'];
    
    if (info.subject) {
        const lowerSubject = info.subject.toLowerCase();
        if (highRiskKeywords.some(w => lowerSubject.includes(w))) {
            score += 15;
            reasons.push({text: "Mots-clés de pression/urgence dans le sujet", score: 15, explanation: "Le sujet contient des mots souvent utilisés pour créer un sentiment d'urgence artificiel."});
        } else if (mediumRiskKeywords.some(w => lowerSubject.includes(w))) {
            score += 5; // Score réduit pour les termes administratifs courants
            reasons.push({text: "Sujet sensible (Financier/Compte)", score: 5, explanation: "Le sujet concerne des éléments sensibles (financier, compte)."});
        }
    }

    // Free Provider Mismatch (Gmail/Yahoo sent via PHP/Script)
    const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'orange.fr', 'wanadoo.fr', 'sfr.fr', 'free.fr'];
    if (fromEmail && freeProviders.some(p => fromEmail.endsWith(p))) {
        if (info.mailer && (info.mailer.toLowerCase().includes('php') || info.mailer.toLowerCase().includes('mailer') || info.mailer.toLowerCase().includes('script'))) {
            score += 25;
            reasons.push({text: "Adresse gratuite utilisée via un script d'envoi", score: 25, explanation: "L'email semble provenir d'un service gratuit mais a été envoyé via un script automatisé."});
        }
    }

    // X-Mailer Checks
    if (info.mailer && (info.mailer.toLowerCase().includes('php') || info.mailer.toLowerCase().includes('script'))) {
        score += 20;
        reasons.push({text: "Envoyé via un script (PHP/Mailer)", score: 20, explanation: "L'email a été envoyé via un script ou un logiciel de mailing, pas un client mail standard."});
    }

    // Priority High
    if (info.priority && info.priority.includes('1')) {
        score += 10;
        reasons.push({text: "Marqué comme haute priorité (X-Priority: 1)", score: 10, explanation: "L'expéditeur a marqué ce message comme 'Haute Priorité' pour attirer l'attention."});
    }

    // X-Spam-Status
    if (info.spamStatus && info.spamStatus.toLowerCase().includes('yes')) {
        score += 50;
        reasons.push({text: "Marqué comme SPAM par un filtre en amont", score: 50, explanation: "Un filtre antispam précédent a déjà classé ce message comme indésirable."});
    }

    return { score: Math.max(0, Math.min(score, 100)), reasons: reasons };
}

function renderResults(info, riskData, raw, hops, headers) {
    document.getElementById('inputSection').style.display = 'none';
    document.getElementById('navActions').style.display = 'flex';
    document.getElementById('results').style.display = 'block';
    const risk = riskData.score;
    
    // Text Fields
    document.getElementById('resSubject').textContent = info.subject;
    document.getElementById('resFrom').textContent = info.from;
    document.getElementById('resTo').textContent = info.to;
    document.getElementById('resDate').textContent = info.date;
    document.getElementById('resMessageId').textContent = info.messageId;

    // Content Type / Attachments
    const rowType = document.getElementById('rowContentType');
    const cType = info.contentType.toLowerCase();
    // Improved detection: only multipart/mixed or explicit non-text/non-multipart main types
    const isMixed = cType.includes('multipart/mixed');
    const isAttachment = info.contentDisposition.toLowerCase().includes('attachment');
    
    if (isMixed || isAttachment) {
        rowType.style.display = 'flex';
        document.getElementById('resContentType').innerHTML = '<span class="badge badge-info">Pièces jointes détectées</span>';
    } else {
        rowType.style.display = 'none';
    }
    
    // Unsubscribe Link
    const unsub = info.listUnsubscribe !== 'Non trouvé' ? info.listUnsubscribe : '-';
    const unsubMatch = unsub.match(/<((https?|mailto):[^>]+)>/);
    const unsubUrl = unsubMatch ? unsubMatch[1] : null;
    document.getElementById('resUnsub').innerHTML = unsubUrl 
        ? `<a href="${unsubUrl}" target="_blank" style="color:var(--primary); text-decoration:none;">Lien détecté ↗</a>` 
        : (unsub !== '-' ? `<span title="${unsub.replace(/"/g, '&quot;')}">Présent (Non cliquable)</span>` : '-');

    document.getElementById('resReturn').textContent = info.returnPath;

    // Badges
    const setAuthColor = (id, status) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (status === 'PASS') el.style.color = 'var(--success)';
        else if (status === 'FAIL') el.style.color = 'var(--danger)';
        else if (status === 'SOFTFAIL' || status === 'NEUTRAL' || status === 'NONE') el.style.color = 'var(--warning)';
        else el.style.color = 'var(--text-light)';
    };

    document.getElementById('resSPF').innerHTML = getBadge(info.spf.status) + `<div class="auth-details">${info.spf.details}</div>`;
    setAuthColor('labelSPF', info.spf.status);
    document.getElementById('resDKIM').innerHTML = getBadge(info.dkim.status) + `<div class="auth-details">${info.dkim.details}</div>`;
    setAuthColor('labelDKIM', info.dkim.status);
    document.getElementById('resDMARC').innerHTML = getBadge(info.dmarc.status) + `<div class="auth-details">${info.dmarc.details}</div>`;
    setAuthColor('labelDMARC', info.dmarc.status);

    // Raw
    document.getElementById('rawHeaders').textContent = raw;

    // Score Animation
    const circlePath = document.getElementById('scoreCirclePath');
    const scoreText = document.getElementById('scoreText');
    const verdict = document.getElementById('scoreVerdict');
    
    let color = '#10b981'; // Green
    let text = 'Sûr';
    
    if (risk > 30) { color = '#f59e0b'; text = 'Suspect'; } // Orange
    if (risk > 60) { color = '#ef4444'; text = 'Critique'; } // Red

    circlePath.style.stroke = color;
    scoreText.style.fill = color;
    verdict.style.color = color;
    verdict.textContent = text;

    // Risk Reasons
    const riskSection = document.getElementById('riskSection');
    const riskDetailsList = document.getElementById('riskDetailsList');
    riskDetailsList.innerHTML = '';

    if (riskData.reasons.length > 0) {
        riskSection.style.display = 'block';
        riskData.reasons.forEach(r => {
            riskDetailsList.innerHTML += `
                <div style="margin-bottom: 8px; border-bottom: 1px solid var(--border); padding-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-weight: 600;">${r.text}</span>
                        <span class="badge badge-danger">+${r.score}%</span>
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-light); font-style: italic;">${r.explanation}</div>
                </div>`;
        });
    } else {
        riskSection.style.display = 'none';
    }

    // Render Hops
    const timeline = document.getElementById('hopsTimeline');
    timeline.innerHTML = '';
    if (hops.length === 0) {
        document.getElementById('hopsTitle').textContent = 'Cheminement du Mail (Hops)';
        timeline.innerHTML = '<div style="color: var(--text-light);">Aucune information de routage (Received) trouvée.</div>';
    } else {
        // Calculate total duration
        let totalDuration = 0;
        if (hops.length > 1 && hops[0].date && hops[hops.length-1].date) {
            totalDuration = (hops[hops.length-1].date - hops[0].date) / 1000;
        }
        document.getElementById('hopsTitle').innerHTML = `Cheminement du Mail (Hops) <span class="badge badge-info" style="font-size: 0.8rem; vertical-align: middle; margin-left: 10px;">Durée: ${totalDuration.toFixed(1)}s</span>`;

        hops.forEach((hop, index) => {
            const delayText = hop.delay !== null ? `+ ${hop.delay.toFixed(1)}s` : '';
            const delayStyle = hop.delay > 10 ? 'color: var(--warning); font-weight:bold;' : 'color: var(--text-light);';
            const ipBadge = hop.isPrivate ? '<span class="badge badge-private">LAN / Privé</span>' : '';
            
            timeline.innerHTML += `
                <div class="hop">
                    <div class="hop-dot"></div>
                    <div class="hop-content">
                        <div class="hop-header">
                            <span>${index + 1}. ${hop.by}</span>
                            <span style="font-size:0.8rem; opacity:0.7">${hop.date ? hop.date.toLocaleString() : ''}</span>
                        </div>
                        <div class="hop-details">
                            <div>De: ${hop.from}</div>
                            <div>IP: ${hop.ip || 'N/A'} ${ipBadge}</div>
                            ${hop.with ? `<div>Via: ${hop.with}</div>` : ''}
                            ${delayText ? `<div class="hop-delay" style="${delayStyle}">Délai: ${delayText}</div>` : ''}
                        </div>
                    </div>
                </div>
            `;
        });
    }

    // Animate number
    let current = 0;
    scoreText.textContent = '0%';
    circlePath.setAttribute('stroke-dasharray', '0, 100');
    const interval = setInterval(() => {
        if (current >= risk) clearInterval(interval);
        else {
            current++;
            scoreText.textContent = current + '%';
            circlePath.setAttribute('stroke-dasharray', `${current}, 100`);
        }
    }, 15);
    
    // Render All Headers
    const allHeadersContainer = document.getElementById('allHeadersContainer');
    allHeadersContainer.innerHTML = '';
    const sortedKeys = Object.keys(headers).sort();
    
    sortedKeys.forEach(key => {
        const val = headers[key];
        const valStr = Array.isArray(val) ? val.join('\n') : val;
        
        const row = document.createElement('div');
        row.className = 'header-list-row';
        row.innerHTML = `
            <div class="header-list-key" style="display:flex; align-items:center; justify-content:space-between;">
                <span>${key}</span>
                <button class="nav-btn-secondary" style="padding:2px 6px; font-size:0.7rem; border:none;" onclick="copyToClipboard(this.parentElement.nextElementSibling.textContent, this)" title="Copier">
                    <i class="fa-regular fa-copy"></i>
                </button>
            </div>
            <div class="header-list-value"></div>
        `;
        row.querySelector('.header-list-value').textContent = valStr;
        allHeadersContainer.appendChild(row);
    });
}

function getBadge(status) {
    let cls = 'badge-warning';
    if (status === 'PASS') cls = 'badge-success';
    if (status === 'FAIL') cls = 'badge-danger';
    return `<span class="badge ${cls}">${status}</span>`;
}

function parseHops(headers) {
    let received = headers['received'];
    if (!received) return [];
    if (!Array.isArray(received)) received = [received];

    const hops = received.map(r => {
        // Extract Date (after last semicolon)
        const dateMatch = r.match(/;\s*([^;]+)$/);
        const dateStr = dateMatch ? dateMatch[1].trim() : null;
        const date = dateStr ? new Date(dateStr) : null;

        // Extract IP
        const ipMatch = r.match(/\[([a-fA-F0-9:.]+)\]/) || r.match(/\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\)/);
        
        // Extract By
        const byMatch = r.match(/\bby\s+([^\s;]+)/i);
        
        // Extract From
        const fromMatch = r.match(/\bfrom\s+([^\s;]+)/i);

        // Extract With
        const withMatch = r.match(/\bwith\s+([^\s;]+)/i);

        const ip = ipMatch ? ipMatch[1] : null;
        
        // Check private IP
        let isPrivate = false;
        if (ip) {
            if (ip.match(/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|fe80:|fc00:|fd00:)/)) {
                isPrivate = true;
            }
        }

        return {
            date: date,
            ip: ip,
            isPrivate: isPrivate,
            by: byMatch ? byMatch[1] : '?',
            from: fromMatch ? fromMatch[1] : '?',
            with: withMatch ? withMatch[1] : null
        };
    });

    // Sort by date asc (oldest first = sender)
    hops.sort((a, b) => (a.date && b.date) ? a.date - b.date : 0);

    // Calculate delays
    for (let i = 0; i < hops.length; i++) {
        if (i === 0) {
            hops[i].delay = 0;
        } else {
            if (hops[i].date && hops[i-1].date) {
                hops[i].delay = (hops[i].date - hops[i-1].date) / 1000; // seconds
            } else {
                hops[i].delay = null;
            }
        }
    }
    
    return hops;
}

function exportPDF() {
    window.print();
}

function toggleRaw() {
    const el = document.getElementById('rawHeaders');
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
