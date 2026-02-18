window.CtbI18n?.init();

const src = document.getElementById('src');
const out = document.getElementById('out');

function defangText(text) {
    return text
        .replace(/https?:\/\//gi, (m) => m.replace('://', '[://]'))
        .replace(/\./g, '[.]')
        .replace(/@/g, '[@]');
}

function refangText(text) {
    return text
        .replace(/\[\.\]/g, '.')
        .replace(/\[@\]/g, '@')
        .replace(/\[:\/\/\]/gi, '://');
}

document.getElementById('defangBtn').addEventListener('click', () => {
    out.value = defangText(src.value);
});

document.getElementById('refangBtn').addEventListener('click', () => {
    out.value = refangText(src.value);
});

document.getElementById('copyBtn').addEventListener('click', async (e) => {
    e.preventDefault();
    if (!out.value) return;
    await navigator.clipboard.writeText(out.value);
});
