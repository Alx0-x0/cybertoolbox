const fileInput = document.getElementById('fileInput');
const dropZone = document.getElementById('dropZone');
const browseBtn = document.getElementById('browseBtn');
const selectedInfo = document.getElementById('selectedInfo');
const algoSelect = document.getElementById('algoSelect');
const expectedInput = document.getElementById('expectedInput');
const computeBtn = document.getElementById('computeBtn');
const hashTable = document.getElementById('hashTable');
const verifyResult = document.getElementById('verifyResult');
let selectedFiles = [];
let isComputing = false;
window.CtbI18n?.init();
const t = (k, f) => window.CtbI18n?.t(k, f) || f;

function toHex(buffer) {
    return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / (1024 ** i)).toFixed(i ? 2 : 0)} ${u[i]}`;
}

async function digest(file, algo) {
    const data = await file.arrayBuffer();
    return toHex(await crypto.subtle.digest(algo, data));
}

function setSelectedFiles(files) {
    selectedFiles = [...files];
    const totalSize = selectedFiles.reduce((acc, f) => acc + f.size, 0);
    if (!selectedFiles.length) {
        selectedInfo.textContent = t('tool.hash.none', 'No file selected');
        return;
    }
    const preview = selectedFiles.slice(0, 3).map((f) => f.name).join(', ');
    const suffix = selectedFiles.length > 3 ? ` +${selectedFiles.length - 3}` : '';
    selectedInfo.textContent = `${selectedFiles.length} ${t('tool.password.file_count', 'file(s)')} • ${formatBytes(totalSize)} • ${preview}${suffix}`;
}

function renderRows(rows) {
    hashTable.innerHTML = rows.map((r, idx) => `
        <div class="hash-row">
            <h3>${r.name} <span class="text-light">(${formatBytes(r.size)})</span></h3>
            ${['SHA-256', 'SHA-1', 'SHA-512'].map((algo) => `
                <div class="hash-item">
                    <span>${algo}</span>
                    <code>${r.hashes[algo]}</code>
                    <button type="button" data-copy="${r.hashes[algo]}"><i class="fa-regular fa-copy"></i></button>
                </div>
            `).join('')}
            <div class="hash-item">
                <span>Checksums</span>
                <code>${r.hashes['SHA-256']}  ${r.name}</code>
                <button type="button" data-copy="${r.hashes['SHA-256']}  ${r.name}"><i class="fa-regular fa-copy"></i></button>
            </div>
            ${idx === 0 ? '<div class="text-light" style="font-size:12px; margin-top:6px;">Verification is run against first selected file.</div>' : ''}
        </div>
    `).join('');
}

function verify(firstRow) {
    const expected = expectedInput.value.trim().toLowerCase();
    if (!expected) {
        verifyResult.style.display = 'none';
        return;
    }

    const algo = algoSelect.value;
    const actual = (firstRow.hashes[algo] || '').toLowerCase();
    const ok = expected === actual;
    verifyResult.style.display = 'block';
    verifyResult.className = `result-box ${ok ? 'success' : 'danger'}`;
    verifyResult.textContent = ok
        ? `${t('tool.hash.match', 'Match')} (${algo})`
        : `${t('tool.hash.mismatch', 'Mismatch')} (${algo}) - ${t('tool.hash.expected_mismatch', 'expected hash does not match')}`;
}

computeBtn.addEventListener('click', async () => {
    if (!selectedFiles.length || isComputing) return;
    isComputing = true;

    computeBtn.disabled = true;
    computeBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${t('tool.hash.computing', 'Computing...')}`;

    const rows = [];
    for (const f of selectedFiles) {
        const hashes = {};
        hashes['SHA-256'] = await digest(f, 'SHA-256');
        hashes['SHA-1'] = await digest(f, 'SHA-1');
        hashes['SHA-512'] = await digest(f, 'SHA-512');
        rows.push({ name: f.name, size: f.size, hashes });
    }

    renderRows(rows);
    verify(rows[0]);

    computeBtn.disabled = false;
    computeBtn.innerHTML = `<i class="fa-solid fa-fingerprint"></i> ${t('tool.hash.compute', 'Compute')}`;
    isComputing = false;
});

algoSelect.addEventListener('change', () => {
    const firstCode = hashTable.querySelector('.hash-row');
    if (!firstCode) return;
    if (!selectedFiles.length) return;
    computeBtn.click();
});

hashTable.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    await navigator.clipboard.writeText(btn.dataset.copy);
});

browseBtn.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
    }
});

fileInput.addEventListener('change', () => {
    setSelectedFiles(fileInput.files);
    if (selectedFiles.length) computeBtn.click();
});

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    setSelectedFiles(e.dataTransfer.files);
    if (selectedFiles.length) computeBtn.click();
});

document.addEventListener('ctb:lang-change', () => {
    setSelectedFiles(selectedFiles);
    computeBtn.innerHTML = `<i class="fa-solid fa-fingerprint"></i> ${t('tool.hash.compute', 'Compute')}`;
});
