// --- Variables Globales ---
let map;
let marker;
let currentTileLayer;

// --- Éléments du DOM ---
const dom = {
    ipInput: document.getElementById('ipInput'),
    searchBtn: document.getElementById('searchBtn'),
    btnText: document.getElementById('btnText'),
    btnLoader: document.getElementById('btnLoader'),
    errorMsg: document.getElementById('errorMsg'),
    // Champs d'affichage
    copyBtn: document.getElementById('copyBtn'),
    ip: document.getElementById('displayIP'),
    type: document.getElementById('ipType'),
    location: document.getElementById('displayLocation'),
    region: document.getElementById('displayRegion'),
    flag: document.getElementById('flag'),
    isp: document.getElementById('displayISP'),
    asn: document.getElementById('displayASN'),
    lat: document.getElementById('displayLat'),
    lon: document.getElementById('displayLon'),
    timezone: document.getElementById('displayTimezone')
};

// --- Initialisation de la carte ---
function initMap() {
    // Vue par défaut (0,0) avant chargement des données
    map = L.map('map').setView([20, 0], 2);

    // Icône personnalisée pour le marqueur
    const customIcon = L.icon({
        iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png',
        shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/images/marker-shadow.png',
        iconSize: [25, 41],
        iconAnchor: [12, 41],
        popupAnchor: [1, -34],
        shadowSize: [41, 41]
    });

    marker = L.marker([20, 0], { icon: customIcon }).addTo(map);
    
    // Initialiser les tuiles selon le thème actuel
    updateMapTiles();
}

// --- Configuration des APIs (Redondance) ---
const providers = [
    {
        name: 'ipwho.is', // Prioritaire
        getUrl: (ip) => `https://ipwho.is/${ip}`,
        validate: (data) => data.success !== false,
        normalize: (data) => ({
            ip: data.ip,
            version: data.type,
            city: data.city,
            region: data.region,
            country_name: data.country,
            country_code: data.country_code,
            postal: data.postal,
            org: data.connection?.isp || data.connection?.org,
            asn: data.connection?.asn ? `AS${data.connection.asn}` : '',
            latitude: data.latitude,
            longitude: data.longitude,
            timezone: data.timezone?.id || data.timezone,
        })
    },
    {
        name: 'ipapi.co', // Fallback
        getUrl: (ip) => ip ? `https://ipapi.co/${ip}/json/` : `https://ipapi.co/json/`,
        validate: (data) => !data.error,
        normalize: (data) => ({
            ip: data.ip,
            version: data.version,
            city: data.city,
            region: data.region,
            country_name: data.country_name,
            country_code: data.country_code,
            postal: data.postal,
            org: data.org,
            asn: data.asn,
            latitude: data.latitude,
            longitude: data.longitude,
            timezone: data.timezone,
        })
    }
];

// --- Fonction de récupération des données (API) ---
async function getIPData(ipAddress = '') {
    setLoading(true);
    hideError();


    let lastError;
    let success = false;

    // On essaie les fournisseurs un par un
    for (const provider of providers) {
        try {
            const url = provider.getUrl(ipAddress);
            const response = await fetch(url);
            
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const rawData = await response.json();
            
            if (!provider.validate(rawData)) {
                throw new Error(rawData.message || rawData.reason || "Erreur API");
            }

            const data = provider.normalize(rawData);

            updateUI(data);
            updateMap(data.latitude, data.longitude, data.city);
            

            success = true;
            break; 

        } catch (error) {
            console.warn(`Provider ${provider.name} failed:`, error);
            lastError = error;
        }
    }

    if (!success) showError(lastError ? lastError.message : "Impossible de localiser l'IP.");
    setLoading(false);
}

// --- Mise à jour de l'interface ---
function updateUI(data) {
    dom.ip.textContent = data.ip || 'N/A';
    dom.type.textContent = data.version || 'N/A';
    
    dom.location.textContent = `${data.city || '?'}, ${data.country_name || '?'}`;
    dom.region.textContent = `${data.region || '?'}, ${data.postal || ''}`;
    
    if (data.country_code) {
        dom.flag.src = `https://flagcdn.com/h40/${data.country_code.toLowerCase()}.png`;
        dom.flag.style.display = 'inline-block';
    } else {
        dom.flag.style.display = 'none';
    }

    dom.isp.textContent = data.org || 'N/A';
    dom.isp.title = data.org || '';
    dom.asn.textContent = data.asn || 'N/A';

    dom.lat.textContent = data.latitude || 'N/A';
    dom.lon.textContent = data.longitude || 'N/A';
    dom.timezone.textContent = data.timezone || 'N/A';
}

// --- Mise à jour de la carte ---
function updateMap(lat, lon, city) {
    if (lat && lon) {
        const newLatLng = new L.LatLng(lat, lon);
        marker.setLatLng(newLatLng);
        marker.bindPopup(`<b>${city || 'Localisation'}</b><br>Lat: ${lat}, Lon: ${lon}`).openPopup();
        
        map.flyTo(newLatLng, 13, {
            animate: true,
            duration: 1.5
        });
    }
}

// --- Gestion des états (Loading / Error) ---
function setLoading(isLoading) {
    if (isLoading) {
        dom.searchBtn.disabled = true;
        dom.btnText.style.display = 'none';
        dom.btnLoader.style.display = 'inline-block';
        dom.ipInput.disabled = true;
    } else {
        dom.searchBtn.disabled = false;
        dom.btnText.style.display = 'inline';
        dom.btnLoader.style.display = 'none';
        dom.ipInput.disabled = false;
        dom.ipInput.focus();
    }
}

function showError(message) {
    dom.errorMsg.textContent = `Erreur : ${message}`;
    dom.errorMsg.style.display = 'block';
}

function hideError() {
    dom.errorMsg.style.display = 'none';
}

// --- Validation IP simple ---
function isValidIP(ip) {
    if(ip.trim() === "") return false;
    return true;
}

function updateMapTiles() {
    if (currentTileLayer) map.removeLayer(currentTileLayer);
    
    // Force dark theme tiles
    const tileUrl = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';

    currentTileLayer = L.tileLayer(tileUrl, {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(map);
}

// --- Écouteurs d'événements ---
window.addEventListener('DOMContentLoaded', () => {
    initMap();
    getIPData();
});

dom.searchBtn.addEventListener('click', () => {
    const ip = dom.ipInput.value.trim();
    getIPData(ip);
});

dom.ipInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        dom.searchBtn.click();
    }
});

dom.copyBtn.addEventListener('click', () => {
    const ip = dom.ip.textContent;
    if (ip && ip !== '---') {
        navigator.clipboard.writeText(ip);
        const originalHTML = dom.copyBtn.innerHTML;
        dom.copyBtn.innerHTML = `<i class="fa-solid fa-check" style="color: var(--success);"></i>`;
        setTimeout(() => dom.copyBtn.innerHTML = originalHTML, 2000);
    }
});
