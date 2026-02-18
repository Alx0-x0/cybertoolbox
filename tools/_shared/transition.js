document.addEventListener('DOMContentLoaded', () => {
    // 1. Create transition overlay
    const overlay = document.createElement('div');
    overlay.id = 'transition-overlay';
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background: #030712; z-index: 99999;
        display: flex; align-items: center; justify-content: center;
        opacity: 0; pointer-events: none; transition: opacity 0.3s ease;
    `;
    overlay.innerHTML = `
        <div style="text-align:center; display:flex; flex-direction:column; align-items:center; gap:1rem;">
            <div style="width:40px; height:40px; border:3px solid rgba(148,163,184,0.1); border-top-color:#818cf8; border-radius:50%; animation:ctb-spin 0.8s linear infinite;"></div>
            <div style="color:#818cf8; font-family:'Inter',sans-serif; font-size:0.8rem; font-weight:600; letter-spacing:0.15em; text-transform:uppercase; animation:ctb-pulse 1.5s ease-in-out infinite;">Loading</div>
        </div>
        <style>
            @keyframes ctb-spin { to { transform: rotate(360deg); } }
            @keyframes ctb-pulse { 50% { opacity: 0.5; } }
        </style>
    `;
    document.body.appendChild(overlay);

    // 2. Intercept link clicks
    document.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            const target = link.getAttribute('target');

            if (!href || href.startsWith('#') || href.startsWith('javascript:') || target === '_blank') return;

            e.preventDefault();
            overlay.style.opacity = '1';
            overlay.style.pointerEvents = 'all';

            setTimeout(() => { window.location.href = href; }, 400);
        });
    });

    // 3. Handle browser back button (bfcache)
    window.addEventListener('pageshow', (e) => {
        if (e.persisted) { overlay.style.opacity = '0'; overlay.style.pointerEvents = 'none'; }
    });
});
