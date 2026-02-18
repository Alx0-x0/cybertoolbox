(function () {
    const t = (key) => window.CtbI18n?.t(key) || key;

    const domainInput = document.getElementById('domainInput');
    const lookupBtn = document.getElementById('lookupBtn');
    const btnText = document.getElementById('btnText');
    const btnLoader = document.getElementById('btnLoader');
    const errorMsg = document.getElementById('errorMsg');
    const results = document.getElementById('results');

    function extractDomain(input) {
        let cleaned = input.trim().toLowerCase();
        cleaned = cleaned.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
        return cleaned;
    }

    function formatDate(dateStr) {
        if (!dateStr) return '---';
        try {
            const d = new Date(dateStr);
            return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
        } catch { return dateStr; }
    }

    function showError(msg) {
        errorMsg.textContent = msg;
        errorMsg.style.display = 'block';
        results.style.display = 'none';
    }

    function hideError() {
        errorMsg.style.display = 'none';
    }

    function setLoading(loading) {
        btnText.style.display = loading ? 'none' : 'inline';
        btnLoader.style.display = loading ? 'inline-block' : 'none';
        lookupBtn.disabled = loading;
        domainInput.disabled = loading;
    }

    async function lookup() {
        const domain = extractDomain(domainInput.value);
        if (!domain || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) {
            showError(t('tool.vt.invalid_format'));
            return;
        }

        hideError();
        setLoading(true);
        results.style.display = 'none';

        try {
            const resp = await fetch(`https://rdap.org/domain/${domain}`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            displayResults(data, domain);
        } catch (err) {
            showError(t('tool.whois.error') + ' ' + err.message);
        } finally {
            setLoading(false);
        }
    }

    function displayResults(data, domain) {
        document.getElementById('displayDomain').textContent = data.ldhName || domain;

        // Registrar
        const registrar = data.entities?.find(e => e.roles?.includes('registrar'));
        const registrarName = registrar?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3]
            || registrar?.handle || '---';
        document.getElementById('displayRegistrar').textContent = registrarName;

        // Dates
        const events = data.events || [];
        const creation = events.find(e => e.eventAction === 'registration')?.eventDate;
        const expiration = events.find(e => e.eventAction === 'expiration')?.eventDate;
        const updated = events.find(e => e.eventAction === 'last changed')?.eventDate;
        document.getElementById('displayCreation').textContent = formatDate(creation);
        document.getElementById('displayExpiration').textContent = formatDate(expiration);
        document.getElementById('displayUpdated').textContent = formatDate(updated);

        // Nameservers
        const nsContainer = document.getElementById('displayNameservers');
        const nameservers = data.nameservers || [];
        if (nameservers.length > 0) {
            nsContainer.innerHTML = nameservers.map(ns =>
                `<span class="ns-chip"><i class="fa-solid fa-server" style="font-size:0.6rem;color:var(--primary);"></i> ${escapeHtml(ns.ldhName || ns.objectClassName || '---')}</span>`
            ).join('');
        } else {
            nsContainer.textContent = '---';
        }

        // Status
        const statusContainer = document.getElementById('displayStatus');
        const statuses = data.status || [];
        if (statuses.length > 0) {
            statusContainer.innerHTML = statuses.map(s =>
                `<span class="status-chip">${escapeHtml(s)}</span>`
            ).join('');
        } else {
            statusContainer.textContent = '---';
        }

        // Raw
        document.getElementById('rawOutput').textContent = JSON.stringify(data, null, 2);

        results.style.display = 'block';
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    lookupBtn.addEventListener('click', lookup);
    domainInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); lookup(); }
    });
})();
