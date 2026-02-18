/**
 * Page Transition Module
 * Handles smooth transitions between pages
 */

export class PageTransition {
    constructor() {
        this.overlay = null;
        this.init();
    }

    init() {
        this.createOverlay();
        this.attachEventListeners();
    }

    createOverlay() {
        this.overlay = document.createElement('div');
        this.overlay.id = 'page-transition-overlay';
        this.overlay.className = 'page-transition-overlay';
        this.overlay.innerHTML = `
            <div class="transition-loader">
                <div class="spinner-circle"></div>
                <p class="transition-text">>_ LOADING</p>
            </div>
        `;
        document.body.appendChild(this.overlay);
    }

    attachEventListeners() {
        document.addEventListener('click', (e) => {
            const link = e.target.closest('a');
            if (!link) return;

            const href = link.getAttribute('href');
            const target = link.getAttribute('target');

            // Skip external links, anchors, and JS links
            if (!href || href.startsWith('#') || href.startsWith('javascript:') || target === '_blank') {
                return;
            }

            e.preventDefault();
            this.show();

            setTimeout(() => {
                window.location.href = href;
            }, 400);
        });

        // Handle back button
        window.addEventListener('pageshow', (e) => {
            if (e.persisted) {
                this.hide();
            }
        });
    }

    show() {
        this.overlay.classList.add('active');
    }

    hide() {
        this.overlay.classList.remove('active');
    }
}

// Auto-initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    new PageTransition();
});
