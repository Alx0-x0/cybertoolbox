import { VirusTotalAPI } from '../../src/js/utils/virustotal.js';
import { Toast, Clipboard, DOM, Theme } from '../../src/js/utils/helpers.js';
import { Navigation } from '../../src/js/components/navigation.js';
import { PageTransition } from '../../src/js/components/transitions.js';
const t = (k, f) => window.CtbI18n?.t(k, f) || f;

class VirusTotalScanner {
    constructor() {
        this.vtAPI = new VirusTotalAPI();
        this.history = [];
        this.currentAnalysis = null;
        this.init();
    }

    init() {
        // Initialize theme
        Theme.init();
        window.CtbI18n?.init();
        new Navigation();

        // Load saved API key and history
        this.loadApiKey();
        this.loadHistory();

        // Setup event listeners
        this.setupEventListeners();
        this.updateUIState();
    }

    setupEventListeners() {
        // API Key management
        document.getElementById('save-api-key').addEventListener('click', () => this.saveApiKey());
        document.getElementById('clear-api-key').addEventListener('click', () => this.clearApiKey());
        document.getElementById('test-api-key').addEventListener('click', () => this.testApiKey());
        document.getElementById('toggle-api-config').addEventListener('click', () => this.toggleApiConfig());

        // Analysis
        document.getElementById('analyze-btn').addEventListener('click', () => this.analyze());
        document.getElementById('analysis-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.analyze();
        });

        // History
        document.getElementById('clear-history').addEventListener('click', () => this.clearHistory());

        // Tabs
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.closest('.tab-button').dataset.tab));
        });

        // Copy actions (avoid page jump / form submit side-effects)
        ['overview-content', 'details-content'].forEach((id) => {
            const container = document.getElementById(id);
            container.addEventListener('click', async (e) => {
                const btn = e.target.closest('.copy-btn-inline');
                if (!btn) return;
                e.preventDefault();
                e.stopPropagation();
                await Clipboard.copy(btn.dataset.copy || '', btn);
            });
        });
    }

    loadApiKey() {
        const apiKey = this.vtAPI.getApiKey();
        if (apiKey) {
            document.getElementById('api-key').value = apiKey;
        }
    }

    saveApiKey() {
        const apiKey = document.getElementById('api-key').value.trim();
        
        if (!apiKey) {
            Toast.show(t('tool.vt.enter_api_key', 'Veuillez entrer une clé API'), 'warning');
            return;
        }

        this.vtAPI.setApiKey(apiKey);
        Toast.show(t('tool.vt.api_saved', 'Clé API enregistrée avec succès'), 'success');
        this.updateUIState();
    }

    clearApiKey() {
        if (confirm(t('tool.vt.confirm_delete_api', 'Êtes-vous sûr de vouloir supprimer votre clé API?'))) {
            document.getElementById('api-key').value = '';
            this.vtAPI.setApiKey('');
            localStorage.removeItem('virustotal_api_key');
            Toast.show(t('tool.vt.api_deleted', 'Clé API supprimée'), 'info');
            this.updateUIState();
        }
    }

    async testApiKey() {
        if (!this.vtAPI.hasApiKey()) {
            Toast.show(t('tool.vt.no_api', 'Aucune clé API configurée'), 'warning');
            return;
        }

        const statusEl = document.getElementById('api-status');
        statusEl.innerHTML = `<div class="alert alert-info"><i class="fa-solid fa-circle-notch fa-spin"></i> ${t('tool.vt.testing', 'Test en cours...')}</div>`;

        try {
            // Test with a public IP
            await this.vtAPI.analyzeIP('8.8.8.8');
            statusEl.innerHTML = `<div class="alert alert-success"><i class="fa-solid fa-check-circle"></i> ${t('tool.vt.api_valid', 'Clé API valide et fonctionnelle!')}</div>`;
            Toast.show(t('tool.vt.api_valid_toast', 'Clé API vérifiée avec succès'), 'success');
        } catch (error) {
            statusEl.innerHTML = `<div class="alert alert-danger"><i class="fa-solid fa-exclamation-circle"></i> ${error.message}</div>`;
            Toast.show(t('tool.common.error_prefix', 'Erreur :') + ' ' + error.message, 'error');
        }
    }

    toggleApiConfig() {
        const content = document.getElementById('api-config-content');
        const btn = document.getElementById('toggle-api-config');
        content.classList.toggle('hidden');
        btn.querySelector('i').classList.toggle('fa-chevron-down');
        btn.querySelector('i').classList.toggle('fa-chevron-up');
    }

    async analyze() {
        const input = document.getElementById('analysis-input').value.trim();

        if (!input) {
            Toast.show(t('tool.vt.enter_target', 'Veuillez entrer une ressource à analyser'), 'warning');
            return;
        }

        const inputType = this.vtAPI.detectInputType(input);
        if (!inputType) {
            Toast.show(t('tool.vt.invalid_format', 'Format invalide. Entrez une URL, domaine, IP ou hash.'), 'error');
            return;
        }

        this.showLoading(true);

        try {
            const result = await this.vtAPI.getVendorInfo(input);
            this.currentAnalysis = result;
            this.addToHistory(input, inputType);
            this.displayResults(result);
        } catch (error) {
            Toast.show(t('tool.common.error_prefix', 'Erreur :') + ' ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    displayResults(result) {
        const resultsSection = document.getElementById('results-section');
        const emptyState = document.getElementById('empty-state');
        
        emptyState.style.display = 'none';
        resultsSection.style.display = 'block';

        // Display summary
        this.displaySummary(result);

        // Display overview
        this.displayOverview(result);

        // Display details
        this.displayDetails(result);

        // Display vendors
        this.displayVendors(result);
    }

    displaySummary(result) {
        const { data, type } = result;
        const attributes = data.data?.attributes || {};
        const stats = attributes.last_analysis_stats || {};
        const totalEngines = Object.values(stats).reduce((sum, v) => sum + (Number(v) || 0), 0);
        const malicious = Number(stats.malicious || 0);
        const suspicious = Number(stats.suspicious || 0);
        const harmless = Number(stats.harmless || 0);
        const undetected = Number(stats.undetected || 0);
        const ratio = totalEngines > 0 ? Math.round(((malicious + suspicious) / totalEngines) * 100) : 0;

        const verdict = this.vtAPI.getVerdict(stats);
        const verdictClass = {
            'clean': 'badge-success',
            'suspicious': 'badge-warning',
            'malicious': 'badge-danger',
            'undetected': 'badge-primary'
        }[verdict];

        const summaryCard = document.getElementById('summary-card');
        summaryCard.innerHTML = `
            <div class="summary-content">
                <div class="summary-header">
                    <h3>${t('tool.vt.results_title', 'Analysis Results')}</h3>
                    <span class="badge ${verdictClass}">
                        ${verdict.toUpperCase()} (${type.replace('hash_', '').toUpperCase()})
                    </span>
                </div>

                <div class="summary-stats">
                    <div class="stat-box">
                        <span class="stat-label">${t('tool.vt.malicious', 'Malicious')}</span>
                        <span class="stat-value danger">${malicious}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">${t('tool.vt.suspicious_label', 'Suspicious')}</span>
                        <span class="stat-value warning">${suspicious}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">${t('tool.vt.undetected', 'Undetected')}</span>
                        <span class="stat-value">${undetected}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">${t('tool.vt.harmless', 'Harmless')}</span>
                        <span class="stat-value success">${harmless}</span>
                    </div>
                </div>

                <p class="summary-date">${t('tool.vt.detection_ratio', 'Detection')}: ${ratio}% (${malicious + suspicious}/${totalEngines || 0}) · ${t('tool.vt.analyzed_on', 'Analyzed on')}: ${new Date(result.timestamp).toLocaleString()}</p>
            </div>
        `;
    }

    displayOverview(result) {
        const { data, type } = result;
        const vtData = data.data || {};
        const attributes = data.data?.attributes || {};
        const stats = attributes.last_analysis_stats || {};
        const totalVotes = attributes.total_votes || {};
        const tags = Array.isArray(attributes.tags) ? attributes.tags.join(', ') : 'N/A';
        const reputation = attributes.reputation ?? 'N/A';
        const detection = `${Number(stats.malicious || 0) + Number(stats.suspicious || 0)} / ${Object.values(stats).reduce((a, b) => a + (Number(b) || 0), 0)}`;

        const common = [
            { label: t('tool.vt.vt_id', 'VT Identifier'), value: vtData.id },
            { label: t('tool.vt.type', 'Type'), value: (vtData.type || type).toUpperCase() },
            { label: t('tool.vt.detection', 'Detection'), value: detection },
            { label: t('tool.vt.reputation', 'Reputation'), value: reputation },
            { label: t('tool.vt.community_votes', 'Community Votes'), value: `${totalVotes.harmless ?? 0} clean / ${totalVotes.malicious ?? 0} malicious` },
            { label: t('tool.vt.tags', 'Tags'), value: tags },
            { label: t('tool.vt.last_analysis', 'Last Analysis'), value: this.formatEpoch(attributes.last_analysis_date) }
        ];

        let content = `<h4 class="report-section-title">${t('tool.vt.general_overview', 'General Overview')}</h4><div class="info-grid">`;
        common.forEach((item) => {
            content += this.renderInfoItem(item.label, item.value);
        });
        content += '</div>';

        if (type === 'url') {
            const urlItems = [
                { label: t('tool.vt.url_label', 'URL'), value: attributes.url, mono: true },
                { label: t('tool.vt.final_url', 'Final URL'), value: attributes.last_final_url || attributes.redirection_chain?.[0], mono: true },
                { label: t('tool.vt.title_label', 'Title'), value: attributes.title },
                { label: t('tool.vt.http_code', 'HTTP Code'), value: attributes.last_http_response_code },
                { label: 'Content-Type', value: attributes.last_http_response_content_type },
                { label: t('tool.vt.server', 'Server'), value: attributes.last_http_response_headers?.server },
                { label: t('tool.vt.response_size', 'Response Size'), value: attributes.last_http_response_content_length }
            ];
            content += `<h4 class="report-section-title">${t('tool.vt.url_http', 'URL / HTTP')}</h4><div class="info-grid">`;
            urlItems.forEach((item) => {
                content += this.renderInfoItem(item.label, item.value, item.mono);
            });
            content += '</div>';
        } else if (type === 'domain') {
            const rankEntries = attributes.popularity_ranks ? Object.entries(attributes.popularity_ranks) : [];
            const rankText = rankEntries.length
                ? rankEntries.slice(0, 3).map(([k, v]) => `${k}: #${v.rank ?? 'N/A'}`).join(' · ')
                : 'N/A';
            const domainItems = [
                { label: t('tool.vt.domain_label', 'Domain'), value: vtData.id, mono: true },
                { label: t('tool.vt.registrar', 'Registrar'), value: attributes.registrar },
                { label: t('tool.vt.creation_date', 'Creation Date'), value: this.formatEpoch(attributes.creation_date) },
                { label: t('tool.vt.update_date', 'Update Date'), value: this.formatEpoch(attributes.last_update_date) },
                { label: t('tool.vt.expiration', 'Expiration'), value: this.formatEpoch(attributes.expiration_date) },
                { label: t('tool.vt.whois_date', 'Whois Date'), value: this.formatEpoch(attributes.whois_date) },
                { label: t('tool.vt.dns_records', 'DNS Records'), value: Array.isArray(attributes.last_dns_records) ? attributes.last_dns_records.length : 'N/A' },
                { label: t('tool.vt.popularity', 'Popularity'), value: rankText }
            ];
            content += `<h4 class="report-section-title">${t('tool.vt.domain_whois', 'Domain / Whois')}</h4><div class="info-grid">`;
            domainItems.forEach((item) => {
                content += this.renderInfoItem(item.label, item.value, item.mono);
            });
            content += '</div>';
        } else if (type === 'ip') {
            const ipItems = [
                { label: t('tool.vt.ip_address', 'IP Address'), value: attributes.ip_address || vtData.id, mono: true },
                { label: t('tool.vt.country', 'Country'), value: attributes.country },
                { label: t('tool.vt.continent', 'Continent'), value: attributes.continent },
                { label: 'ASN', value: attributes.asn },
                { label: 'AS Owner', value: attributes.as_owner },
                { label: t('tool.vt.network', 'Network'), value: attributes.network, mono: true },
                { label: 'JARM', value: attributes.jarm, mono: true }
            ];
            content += `<h4 class="report-section-title">${t('tool.vt.ip_network', 'IP / Network')}</h4><div class="info-grid">`;
            ipItems.forEach((item) => {
                content += this.renderInfoItem(item.label, item.value, item.mono);
            });
            content += '</div>';
        } else {
            const hashItems = [
                { label: 'SHA-256', value: attributes.sha256 || vtData.id, mono: true },
                { label: 'SHA-1', value: attributes.sha1, mono: true },
                { label: 'MD5', value: attributes.md5, mono: true },
                { label: t('tool.vt.filename', 'Filename'), value: attributes.meaningful_name || attributes.names?.[0] },
                { label: t('tool.vt.size', 'Size'), value: this.formatBytes(attributes.size) },
                { label: t('tool.vt.type', 'Type'), value: attributes.type_description || attributes.type_tag },
                { label: t('tool.vt.magic', 'Magic'), value: attributes.magic },
                { label: t('tool.vt.first_submission', 'First Submission'), value: this.formatEpoch(attributes.first_submission_date) },
                { label: t('tool.vt.last_submission', 'Last Submission'), value: this.formatEpoch(attributes.last_submission_date) },
                { label: t('tool.vt.submissions', 'Submissions'), value: attributes.times_submitted }
            ];
            content += `<h4 class="report-section-title">${t('tool.vt.file_hash', 'File / Hash')}</h4><div class="info-grid">`;
            hashItems.forEach((item) => {
                content += this.renderInfoItem(item.label, item.value, item.mono);
            });
            content += '</div>';
        }

        document.getElementById('overview-content').innerHTML = content;
    }

    displayDetails(result) {
        const { data, type } = result;
        const vtData = data.data || {};
        const attributes = vtData.attributes || {};
        const stats = attributes.last_analysis_stats || {};

        const detailRows = [
            { label: t('tool.vt.vt_id', 'VT ID'), value: vtData.id, mono: true },
            { label: t('tool.vt.input_type', 'Input Type'), value: type },
            { label: t('tool.vt.status_label', 'Status'), value: attributes.status || 'N/A' },
            { label: t('tool.vt.reputation', 'Reputation'), value: attributes.reputation },
            { label: t('tool.vt.malicious', 'Malicious'), value: stats.malicious },
            { label: t('tool.vt.suspicious_label', 'Suspicious'), value: stats.suspicious },
            { label: t('tool.vt.harmless', 'Harmless'), value: stats.harmless },
            { label: t('tool.vt.undetected', 'Undetected'), value: stats.undetected },
            { label: 'Timeout', value: stats.timeout },
            { label: 'Failure', value: stats.failure },
            { label: t('tool.vt.first_submission', 'First submission'), value: this.formatEpoch(attributes.first_submission_date) },
            { label: t('tool.vt.last_submission', 'Last submission'), value: this.formatEpoch(attributes.last_submission_date) },
            { label: t('tool.vt.last_analysis', 'Last analysis'), value: this.formatEpoch(attributes.last_analysis_date) },
            { label: t('tool.vt.submissions', 'Times submitted'), value: attributes.times_submitted },
            { label: t('tool.vt.threat_severity', 'Threat severity'), value: attributes.threat_severity?.level },
            { label: t('tool.vt.sigma', 'Sigma analyses'), value: Array.isArray(attributes.sigma_analysis_results) ? attributes.sigma_analysis_results.length : undefined },
            { label: t('tool.vt.crowdsourced_ids', 'Crowdsourced IDS'), value: Array.isArray(attributes.crowdsourced_ids_results) ? attributes.crowdsourced_ids_results.length : undefined },
            { label: t('tool.vt.crowdsourced_yara', 'Crowdsourced YARA'), value: Array.isArray(attributes.crowdsourced_yara_results) ? attributes.crowdsourced_yara_results.length : undefined }
        ];

        const extraDns = Array.isArray(attributes.last_dns_records)
            ? attributes.last_dns_records.slice(0, 8).map((r) => `${r.type} ${r.value}`).join(' | ')
            : undefined;
        const cert = attributes.last_https_certificate?.subject?.CN || attributes.last_https_certificate?.issuer?.O;
        detailRows.push({ label: t('tool.vt.dns_preview', 'DNS Records (preview)'), value: extraDns, mono: true });
        detailRows.push({ label: t('tool.vt.tls_cert', 'TLS Certificate'), value: cert });

        let detailsHTML = '<div class="details-table">';
        detailRows.forEach((row) => {
            detailsHTML += this.renderDetailRow(row.label, row.value, row.mono);
        });
        detailsHTML += '</div>';
        document.getElementById('details-content').innerHTML = detailsHTML;
    }

    displayVendors(result) {
        const { data } = result;
        const lastAnalysisResults = data.data?.attributes?.last_analysis_results || {};

        if (Object.keys(lastAnalysisResults).length === 0) {
            document.getElementById('vendors-content').innerHTML =
                `<p class="no-data">${t('tool.vt.no_vendor', 'No vendor results available')}</p>`;
            return;
        }

        // Group vendors by category
        const groups = { malicious: [], suspicious: [], undetected: [], harmless: [], other: [] };

        Object.entries(lastAnalysisResults).forEach(([vendor, res]) => {
            const cat = res.category || 'other';
            (groups[cat] || groups.other).push({ vendor, ...res });
        });

        const categoryConfig = {
            malicious:  { label: t('tool.vt.malicious', 'Malicious'),  icon: 'fa-skull-crossbones', badge: 'danger',  open: true },
            suspicious: { label: t('tool.vt.suspicious_label', 'Suspicious'),       icon: 'fa-triangle-exclamation', badge: 'warning', open: true },
            undetected: { label: t('tool.vt.undetected', 'Undetected'),   icon: 'fa-question-circle', badge: 'info',    open: false },
            harmless:   { label: t('tool.vt.harmless', 'Harmless'),    icon: 'fa-check-circle',    badge: 'success', open: false },
            other:      { label: t('tool.vt.other', 'Other'),          icon: 'fa-circle',          badge: 'default', open: false }
        };

        let html = '';
        for (const [cat, cfg] of Object.entries(categoryConfig)) {
            const items = groups[cat];
            if (!items || items.length === 0) continue;

            const expanded = cfg.open;
            html += `
                <div class="vendor-group">
                    <button type="button" class="vendor-group-toggle ${expanded ? 'expanded' : ''}"
                            onclick="this.classList.toggle('expanded'); this.nextElementSibling.classList.toggle('collapsed');">
                        <div class="vendor-group-header">
                            <i class="fa-solid ${cfg.icon}"></i>
                            <span>${cfg.label}</span>
                            <span class="badge badge-${cfg.badge}">${items.length}</span>
                        </div>
                        <i class="fa-solid fa-chevron-down vendor-chevron"></i>
                    </button>
                    <div class="vendor-group-content ${expanded ? '' : 'collapsed'}">
                        <div class="vendor-grid">
                            ${items.map(item => `
                                <div class="vendor-chip vendor-chip-${cfg.badge}">
                                    <span class="vendor-chip-name">${item.vendor}</span>
                                    ${item.result && item.result !== 'clean' && item.result !== 'unrated'
                                        ? `<span class="vendor-chip-detail">${item.result}</span>` : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
        }

        document.getElementById('vendors-content').innerHTML = html;
    }

    renderInfoItem(label, value, monospace = false) {
        const safeValue = this.escapeHtml(value ?? 'N/A');
        const rawValue = String(value ?? 'N/A');
        const valueClass = monospace ? 'info-value monospace' : 'info-value';
        return `
            <div class="info-item">
                <span class="info-label">${this.escapeHtml(label)}</span>
                <div class="info-value-row">
                    <span class="${valueClass}">${safeValue}</span>
                    <button type="button" class="copy-btn-inline" data-copy="${this.escapeHtml(rawValue)}" title="${t('tool.common.copy', 'Copy')}">
                        <i class="fa-regular fa-copy"></i>
                    </button>
                </div>
            </div>
        `;
    }

    renderDetailRow(label, value, monospace = false) {
        const safeValue = this.escapeHtml(value ?? 'N/A');
        const rawValue = String(value ?? 'N/A');
        const valueClass = monospace ? 'detail-value monospace' : 'detail-value';
        return `
            <div class="detail-row">
                <span class="detail-label">${this.escapeHtml(label)}</span>
                <div class="detail-value-row">
                    <span class="${valueClass}">${safeValue}</span>
                    <button type="button" class="copy-btn-inline" data-copy="${this.escapeHtml(rawValue)}" title="${t('tool.common.copy', 'Copy')}">
                        <i class="fa-regular fa-copy"></i>
                    </button>
                </div>
            </div>
        `;
    }

    formatEpoch(value) {
        if (!value || Number.isNaN(Number(value))) return 'N/A';
        return new Date(Number(value) * 1000).toLocaleString();
    }

    formatBytes(bytes, decimals = 2) {
        if (!Number(bytes)) return 'N/A';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
    }

    escapeHtml(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    switchTab(tabName) {
        // Update buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });

        // Update content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `${tabName}-tab`);
        });
    }

    addToHistory(input, type) {
        const entry = {
            input,
            type,
            timestamp: new Date().toLocaleString()
        };

        this.history.unshift(entry);
        if (this.history.length > 20) {
            this.history.pop();
        }

        localStorage.setItem('virustotal_history', JSON.stringify(this.history));
        this.displayHistory();
    }

    loadHistory() {
        const saved = localStorage.getItem('virustotal_history');
        if (saved) {
            this.history = JSON.parse(saved);
            this.displayHistory();
        }
    }

    displayHistory() {
        const historySection = document.getElementById('history-section');
        const historyList = document.getElementById('history-list');

        if (this.history.length === 0) {
            historySection.style.display = 'none';
            return;
        }

        historySection.style.display = 'block';
        historyList.innerHTML = '';

        const typeIcons = { url: 'fa-link', domain: 'fa-globe', ip: 'fa-network-wired', hash: 'fa-fingerprint' };

        this.history.forEach(entry => {
            const chip = document.createElement('span');
            chip.className = 'history-chip';
            chip.title = `${entry.type} - ${entry.timestamp}`;
            const icon = typeIcons[entry.type] || 'fa-circle';
            chip.innerHTML = `<i class="fa-solid ${icon}"></i> ${entry.input}`;
            chip.addEventListener('click', () => {
                document.getElementById('analysis-input').value = entry.input;
                this.analyze();
            });
            historyList.appendChild(chip);
        });
    }

    analyzeFromHistory(input) {
        document.getElementById('analysis-input').value = input;
        this.analyze();
    }

    clearHistory() {
        if (confirm(t('tool.vt.confirm_clear_history', 'Êtes-vous sûr de vouloir effacer l\'historique?'))) {
            this.history = [];
            localStorage.removeItem('virustotal_history');
            document.getElementById('history-section').style.display = 'none';
            Toast.show(t('tool.vt.history_cleared', 'Historique effacé'), 'info');
        }
    }

    showLoading(show) {
        document.getElementById('loading-state').style.display = show ? 'flex' : 'none';
    }

    updateUIState() {
        const hasApiKey = this.vtAPI.hasApiKey();
        document.getElementById('analysis-input').disabled = !hasApiKey;
        document.getElementById('analyze-btn').disabled = !hasApiKey;

        if (!hasApiKey) {
            Toast.show(t('tool.vt.configure_api', 'Veuillez configurer votre clé API pour utiliser l\'outil'), 'info');
        }
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    window.scanner = new VirusTotalScanner();
});

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
        input.placeholder = t('tool.vt.ph_hash', 'Enter Hash (MD5, SHA-1, SHA-256)...');
        if (dropZone) dropZone.style.display = 'block';
    } else if (mode === 'url') {
        input.placeholder = t('tool.vt.ph_url', 'Enter URL (e.g. http://example.com)...');
        if (dropZone) dropZone.style.display = 'none';
    } else if (mode === 'domain') {
        input.placeholder = t('tool.vt.ph_domain', 'Enter domain (e.g. google.com)...');
        if (dropZone) dropZone.style.display = 'none';
    } else if (mode === 'ip') {
        input.placeholder = t('tool.vt.ph_ip', 'Enter IP address (e.g. 8.8.8.8)...');
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
    dropZone.querySelector('p').textContent = t('tool.vt.hashing', 'Computing hash...');
    
    try {
        const arrayBuffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        document.getElementById('searchInput').value = hashHex;
        showToast(`${t('tool.vt.hash_computed', 'Hash computed')}: ${hashHex.substring(0, 10)}...`);
        performScan();
    } catch (err) {
        console.error(err);
        showToast(t('tool.vt.hash_error', 'Error computing hash.'), "error");
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
        showToast(t('tool.vt.no_api_key', 'Please configure your API key first.'), 'error');
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

        // Utilisation d'un proxy CORS pour contourner les restrictions du navigateur
        const targetUrl = `${API_URL_BASE}${endpoint}`;
        const response = await fetch(`${CORS_PROXY}${encodeURIComponent(targetUrl)}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            if (response.status === 401) throw new Error(t('tool.vt.err_invalid_key', 'Invalid API key.'));
            if (response.status === 403) throw new Error(t('tool.vt.err_forbidden', 'Access denied (Proxy or API Key).'));
            if (response.status === 404) throw new Error(t('tool.vt.err_not_found', 'Resource not found on VirusTotal (Never analyzed?).'));
            if (response.status === 429) throw new Error(t('tool.vt.err_quota', 'API quota exceeded.'));
            throw new Error(`${t('tool.vt.err_api', 'API Error')} (${response.status})`);
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
            verdictText.textContent = t('tool.vt.verdict_suspect', 'Suspicious');
            verdictSub.textContent = `${malicious} ${t('tool.vt.engines_flagged', 'security engines flagged this resource.')}`;
        } else {
            color = 'var(--danger)';
            verdictText.textContent = t('tool.vt.verdict_malicious', 'Malicious');
            verdictSub.textContent = `${malicious} ${t('tool.vt.engines_flagged', 'security engines flagged this resource.')}`;
        }
    } else {
        verdictText.textContent = t('tool.vt.verdict_clean', 'Clean');
        verdictSub.textContent = t('tool.vt.no_threat', 'No security engine flagged any threat.');
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
    addInfo(t('tool.vt.last_analysis_label', 'Last Analysis'), date);
    addInfo(t('tool.vt.type', 'Type'), data.type);

    // Specific Data based on Type
    if (data.type === 'file') {
        addInfo(t('tool.vt.size', 'Size'), formatBytes(attr.size));
        addInfo(t('tool.vt.suggested_name', 'Name (Suggested)'), attr.names ? attr.names[0] : attr.meaningful_name);
        addInfo(t('tool.vt.mime_type', 'MIME Type'), attr.type_description);
    } else if (data.type === 'url') {
        addInfo(t('tool.vt.url_label', 'URL'), attr.url);
        addInfo(t('tool.vt.page_title', 'Page Title'), attr.title);
        addInfo(t('tool.vt.server', 'Server'), attr.last_http_response_headers?.server || 'N/A');
    } else if (data.type === 'domain') {
        addInfo(t('tool.vt.registrar', 'Registrar'), attr.registrar);
        addInfo(t('tool.vt.creation_label', 'Creation'), attr.creation_date ? new Date(attr.creation_date * 1000).toLocaleDateString() : 'N/A');
        addInfo(t('tool.vt.reputation', 'Reputation'), attr.reputation);
    } else if (data.type === 'ip_address') {
        addInfo(t('tool.vt.country', 'Country'), attr.country);
        addInfo(t('tool.vt.network', 'Network'), attr.network);
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
