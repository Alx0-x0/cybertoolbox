document.addEventListener('DOMContentLoaded', () => {
    // 1. Injection de l'overlay de chargement
    const overlay = document.createElement('div');
    overlay.id = 'transition-overlay';
    // Styles inline pour garantir l'affichage immédiat sans dépendre du CSS externe chargé
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background: #0d0d0d; z-index: 99999;
        display: flex; align-items: center; justify-content: center;
        opacity: 0; pointer-events: none; transition: opacity 0.3s ease;
    `;
    overlay.innerHTML = `
        <div style="text-align:center; color:#00ff41; font-family:'Share Tech Mono', monospace;">
            <i class="fa-solid fa-circle-notch fa-spin" style="font-size:3rem; margin-bottom:15px; text-shadow: 0 0 15px #00ff41;"></i>
            <div style="font-size:1.2rem; letter-spacing:2px; animation: blink 1s infinite;">>_ SYSTEM ACCESS...</div>
        </div>
        <style>@keyframes blink { 50% { opacity: 0.5; } }</style>
    `;
    document.body.appendChild(overlay);

    // 2. Interception des clics sur les liens
    document.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            const target = link.getAttribute('target');

            // On ignore les liens externes, ancres, ou JS
            if (!href || href.startsWith('#') || href.startsWith('javascript:') || target === '_blank') return;

            e.preventDefault();
            overlay.style.opacity = '1';
            overlay.style.pointerEvents = 'all';

            setTimeout(() => { window.location.href = href; }, 400); // Délai pour l'animation
        });
    });

    // 3. Gestion du bouton "Retour" du navigateur (cache bfcache)
    window.addEventListener('pageshow', (e) => {
        if (e.persisted) { overlay.style.opacity = '0'; overlay.style.pointerEvents = 'none'; }
    });
});