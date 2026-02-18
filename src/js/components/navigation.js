/**
 * Navigation Component
 */

export class Navigation {
    constructor() {
        this.init();
    }

    init() {
        this.setupThemeToggle();
        this.setupMobileMenu();
    }

    setupThemeToggle() {
        const themeBtn = document.getElementById('theme-toggle');
        if (themeBtn) {
            themeBtn.addEventListener('click', () => {
                const current = document.documentElement.getAttribute('data-theme') || 'dark';
                const next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                localStorage.setItem('theme', next);
            });
        }
    }

    setupMobileMenu() {
        const menuBtn = document.getElementById('mobile-menu-toggle');
        const mobileMenu = document.getElementById('mobile-menu');

        if (menuBtn && mobileMenu) {
            menuBtn.addEventListener('click', () => {
                mobileMenu.classList.toggle('active');
            });

            document.addEventListener('click', (e) => {
                if (!e.target.closest('nav') && !e.target.closest('#mobile-menu-toggle')) {
                    mobileMenu.classList.remove('active');
                }
            });
        }
    }
}
