/**
 * VirusTotal API Module
 * Handles all interactions with the VirusTotal API
 */

export class VirusTotalAPI {
    constructor(apiKey = '') {
        this.apiKey = apiKey;
        this.baseUrl = 'https://www.virustotal.com/api/v3';
        this.baseUrlIntel = 'https://www.virustotal.com/gui/home';
    }

    /**
     * Set API Key
     */
    setApiKey(key) {
        this.apiKey = key;
        localStorage.setItem('virustotal_api_key', key);
    }

    /**
     * Get API Key
     */
    getApiKey() {
        return this.apiKey || localStorage.getItem('virustotal_api_key') || '';
    }

    /**
     * Check if API key is set
     */
    hasApiKey() {
        return !!this.getApiKey();
    }

    /**
     * Make API request with CORS bypass via open proxy
     */
    async request(endpoint, method = 'GET', data = null) {
        if (!this.hasApiKey()) {
            throw new Error('API Key not configured');
        }

        const url = `${this.baseUrl}${endpoint}`;
        const options = {
            method,
            headers: {
                'x-apikey': this.getApiKey(),
                'Content-Type': 'application/json'
            }
        };

        if (data && method !== 'GET') {
            options.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(url, options);
            
            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('Clé API invalide');
                } else if (response.status === 429) {
                    throw new Error('Trop de requêtes. Limite API atteinte');
                } else if (response.status === 404) {
                    throw new Error('Ressource non trouvée');
                }
                throw new Error(`Erreur API: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            throw error;
        }
    }

    /**
     * Analyze URL
     */
    async analyzeUrl(url) {
        try {
            const formData = new FormData();
            formData.append('url', url);

            const response = await fetch(`${this.baseUrl}/urls`, {
                method: 'POST',
                headers: {
                    'x-apikey': this.getApiKey()
                },
                body: formData
            });

            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (error) {
            throw error;
        }
    }

    /**
     * Get URL analysis result
     */
    async getUrlAnalysis(urlId) {
        return this.request(`/urls/${urlId}`);
    }

    /**
     * Analyze Domain
     */
    async analyzeDomain(domain) {
        return this.request(`/domains/${domain}`);
    }

    /**
     * Analyze IP
     */
    async analyzeIP(ip) {
        return this.request(`/ip_addresses/${ip}`);
    }

    /**
     * Analyze File Hash (MD5, SHA1, SHA256)
     */
    async analyzeHash(hash) {
        return this.request(`/files/${hash}`);
    }

    /**
     * Determine type of input
     */
    detectInputType(input) {
        input = input.trim();

        // URL
        if (input.startsWith('http://') || input.startsWith('https://')) {
            return 'url';
        }

        // IPv4
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(input)) {
            return 'ip';
        }

        // Hash (MD5, SHA1, SHA256)
        if (/^[a-fA-F0-9]+$/.test(input)) {
            if (input.length === 32) return 'hash_md5';
            if (input.length === 40) return 'hash_sha1';
            if (input.length === 64) return 'hash_sha256';
        }

        // Domain
        if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(input)) {
            return 'domain';
        }

        return null;
    }

    /**
     * Get verdict from analysis stats
     */
    getVerdict(stats) {
        if (!stats) return 'unknown';
        
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const undetected = stats.undetected || 0;

        if (malicious > 0) return 'malicious';
        if (suspicious > 0) return 'suspicious';
        if (undetected > 0) return 'undetected';
        
        return 'clean';
    }

    /**
     * Get vendor information
     */
    async getVendorInfo(input) {
        const type = this.detectInputType(input);
        
        try {
            let data;
            switch (type) {
                case 'url':
                    data = await this.analyzeUrl(input);
                    break;
                case 'domain':
                    data = await this.analyzeDomain(input);
                    break;
                case 'ip':
                    data = await this.analyzeIP(input);
                    break;
                case 'hash_md5':
                case 'hash_sha1':
                case 'hash_sha256':
                    data = await this.analyzeHash(input);
                    break;
                default:
                    throw new Error('Type d\'entrée invalide');
            }

            return {
                type,
                data,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw error;
        }
    }
}
