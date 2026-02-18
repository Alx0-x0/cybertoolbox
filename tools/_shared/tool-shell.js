(function () {
    const GITHUB_URL = 'https://github.com/Alx0-x0/cybertoolbox';

    function getTheme() {
        return localStorage.getItem('theme') || 'dark';
    }

    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        const icon = document.querySelector('#tool-theme-toggle i');
        if (icon) {
            icon.className = theme === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
        }
    }

    function toggleTheme() {
        const next = getTheme() === 'dark' ? 'light' : 'dark';
        setTheme(next);
    }

    function renderHeader() {
        const header = document.getElementById('tool-header-shell');
        if (!header) return;
        header.classList.add('header');

        header.innerHTML = `
            <a href="../../index.html" class="logo">
                <i class="fa-solid fa-arrow-left"></i>
                <span>CyberToolBox</span>
            </a>
            <div class="tool-header-actions">
                <div class="lang-switch" aria-label="Language switch">
                    <button type="button" class="lang-btn btn btn-ghost btn-sm" data-lang-btn="fr" data-i18n="lang.fr">FR</button>
                    <button type="button" class="lang-btn btn btn-ghost btn-sm" data-lang-btn="en" data-i18n="lang.en">EN</button>
                </div>
                <a href="${GITHUB_URL}" target="_blank" class="github-link" data-i18n-title="tool.common.github" title="GitHub">
                    <i class="fa-brands fa-github"></i>
                </a>
                <button type="button" id="tool-theme-toggle" class="lang-btn btn btn-ghost btn-sm" data-i18n-title="tool.common.theme" title="Theme">
                    <i class="fa-solid fa-moon"></i>
                </button>
            </div>
        `;

        const toggleBtn = document.getElementById('tool-theme-toggle');
        if (toggleBtn) toggleBtn.addEventListener('click', toggleTheme);
    }

    function init() {
        renderHeader();
        setTheme(getTheme());
        window.CtbI18n?.init();
    }

    document.addEventListener('DOMContentLoaded', init);
})();
