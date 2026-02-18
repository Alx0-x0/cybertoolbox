/**
 * Utility Functions Module
 * Provides common utilities used across the application
 */

export const Toast = {
    /**
     * Show a toast notification
     * @param {string} message - Message to display
     * @param {string} type - Type of toast (success, error, info, warning)
     * @param {number} duration - Duration in ms (0 = persistent)
     */
    show(message, type = 'info', duration = 3000) {
        const container = document.getElementById('toast-container') || this._createContainer();
        const toast = document.createElement('div');
        toast.className = `toast toast-${type} animate-slide-up`;
        toast.innerHTML = `
            <div class="toast-content">
                <i class="toast-icon fa-solid fa-${this._getIcon(type)}"></i>
                <span>${message}</span>
            </div>
            <button class="toast-close" aria-label="Fermer">&times;</button>
        `;

        container.appendChild(toast);

        toast.querySelector('.toast-close').addEventListener('click', () => {
            toast.remove();
        });

        if (duration > 0) {
            setTimeout(() => toast.remove(), duration);
        }

        return toast;
    },

    _createContainer() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
        return container;
    },

    _getIcon(type) {
        const icons = {
            success: 'circle-check',
            error: 'circle-xmark',
            warning: 'triangle-exclamation',
            info: 'circle-info'
        };
        return icons[type] || 'info-circle';
    }
};

export const Clipboard = {
    /**
     * Copy text to clipboard
     * @param {string} text - Text to copy
     * @param {HTMLElement} button - Button to show feedback on
     */
    async copy(text, button = null) {
        try {
            await navigator.clipboard.writeText(text);
            if (button) {
                const original = button.innerHTML;
                const original_class = button.className;
                button.innerHTML = '<i class="fa-solid fa-check"></i>';
                button.classList.add('btn-success');
                setTimeout(() => {
                    button.innerHTML = original;
                    button.className = original_class;
                }, 1500);
            }
            Toast.show('Copié !', 'success', 2000);
            return true;
        } catch (err) {
            Toast.show('Erreur lors de la copie', 'error');
            console.error('Failed to copy:', err);
            return false;
        }
    }
};

export const Validator = {
    /**
     * Validate email
     */
    isEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },

    /**
     * Validate URL
     */
    isUrl(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    },

    /**
     * Validate IP address (IPv4)
     */
    isIpAddress(ip) {
        return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && 
               ip.split('.').every(num => parseInt(num) <= 255);
    },

    /**
     * Validate domain name
     */
    isDomain(domain) {
        return /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(domain);
    },

    /**
     * Validate hash (MD5, SHA1, SHA256)
     */
    isHash(hash) {
        const hash_length = hash.length;
        return /^[a-fA-F0-9]+$/.test(hash) &&
               (hash_length === 32 || hash_length === 40 || hash_length === 64);
    }
};

export const API = {
    /**
     * Make a GET request
     */
    async get(url, options = {}) {
        try {
            const response = await fetch(url, {
                method: 'GET',
                ...options
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error('API GET error:', error);
            throw error;
        }
    },

    /**
     * Make a POST request
     */
    async post(url, data = {}, options = {}) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                body: JSON.stringify(data),
                ...options
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error('API POST error:', error);
            throw error;
        }
    }
};

export const LocalStorage = {
    /**
     * Save data to localStorage
     */
    set(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch (error) {
            console.error('LocalStorage set error:', error);
            return false;
        }
    },

    /**
     * Get data from localStorage
     */
    get(key, defaultValue = null) {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (error) {
            console.error('LocalStorage get error:', error);
            return defaultValue;
        }
    },

    /**
     * Remove item from localStorage
     */
    remove(key) {
        try {
            localStorage.removeItem(key);
            return true;
        } catch (error) {
            console.error('LocalStorage remove error:', error);
            return false;
        }
    },

    /**
     * Clear localStorage
     */
    clear() {
        try {
            localStorage.clear();
            return true;
        } catch (error) {
            console.error('LocalStorage clear error:', error);
            return false;
        }
    }
};

export const DOM = {
    /**
     * Select single element
     */
    select(selector) {
        return document.querySelector(selector);
    },

    /**
     * Select multiple elements
     */
    selectAll(selector) {
        return document.querySelectorAll(selector);
    },

    /**
     * Create element
     */
    create(tag, options = {}) {
        const element = document.createElement(tag);
        if (options.class) element.className = options.class;
        if (options.id) element.id = options.id;
        if (options.text) element.textContent = options.text;
        if (options.html) element.innerHTML = options.html;
        if (options.attributes) {
            Object.entries(options.attributes).forEach(([key, value]) => {
                element.setAttribute(key, value);
            });
        }
        return element;
    },

    /**
     * Add class
     */
    addClass(element, className) {
        if (typeof element === 'string') element = this.select(element);
        element?.classList.add(className);
    },

    /**
     * Remove class
     */
    removeClass(element, className) {
        if (typeof element === 'string') element = this.select(element);
        element?.classList.remove(className);
    },

    /**
     * Toggle class
     */
    toggleClass(element, className) {
        if (typeof element === 'string') element = this.select(element);
        element?.classList.toggle(className);
    },

    /**
     * Check if element has class
     */
    hasClass(element, className) {
        if (typeof element === 'string') element = this.select(element);
        return element?.classList.contains(className) || false;
    }
};

export const Debounce = {
    /**
     * Debounce a function
     */
    execute(func, delay = 300) {
        let timeoutId;
        return function (...args) {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => func.apply(this, args), delay);
        };
    }
};

export const Theme = {
    /**
     * Get current theme
     */
    getCurrent() {
        return localStorage.getItem('theme') || 'dark';
    },

    /**
     * Set theme
     */
    set(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
    },

    /**
     * Toggle theme
     */
    toggle() {
        const current = this.getCurrent();
        const next = current === 'dark' ? 'light' : 'dark';
        this.set(next);
        return next;
    },

    /**
     * Initialize theme
     */
    init() {
        const theme = this.getCurrent();
        document.documentElement.setAttribute('data-theme', theme);
    }
};
