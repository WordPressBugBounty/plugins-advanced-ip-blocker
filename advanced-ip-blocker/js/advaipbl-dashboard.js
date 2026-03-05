jQuery(document).ready(function ($) {

    const dashboardContainer = $('#advaipbl-dashboard');
    if (!dashboardContainer.length) {
        return;
    }

    // Variables dedicadas para mantener las instancias del mapa y del grupo de capas.
    // Se inicializan una sola vez para todo el ciclo de vida de la página.
    let advaipblMapInstance = null;
    let advaipblMarkersLayer = null;

    const chartColors = [
        '#3498db', '#e74c3c', '#9b59b6', '#2ecc71', '#f1c40f',
        '#1abc9c', '#e67e22', '#34495e', '#7f8c8d', '#c0392b'
    ];

    function initDashboard() {
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            cache: false,
            data: {
                action: 'advaipbl_get_dashboard_stats',
                nonce: window.advaipbl_admin_data.nonces.get_dashboard_stats,
                '_': new Date().getTime()
            },
            success: function (response) {
                if (response.success) {
                    const isolatedData = JSON.parse(JSON.stringify(response.data));
                    renderDashboard(isolatedData);
                } else {
                    showErrorState('Failed to load dashboard data.');
                }
            },
            error: function () {
                showErrorState('AJAX error while loading dashboard data.');
            },
            complete: function () {
                dashboardContainer.find('.advaipbl-loader-wrapper').hide();
                dashboardContainer.find('.advaipbl-dashboard-content').show();
                dashboardContainer.removeClass('advaipbl-dashboard-loading');
            }
        });
    }

    function showErrorState(message) {
        dashboardContainer.find('.advaipbl-dashboard-content').html(
            `<div class="notice notice-error inline"><p>${message}</p></div>`
        ).show();
    }

    function renderDashboard(data) {
        renderSummaryWidget(data.summary);
        renderTimelineWidget(data.timeline);
        renderTopLists(data.top_ips, data.top_countries);
        renderSystemStatus(data.system_status);
        renderLiveAttackMap(data.live_attacks);
    }

    function renderSummaryWidget(summaryData) { const ctx = document.getElementById('advaipbl-attack-type-chart'); if (!ctx || !summaryData || !summaryData.by_type) return; const labels = Object.keys(summaryData.by_type); const values = Object.values(summaryData.by_type); new Chart(ctx, { type: 'doughnut', data: { labels: labels, datasets: [{ label: 'Attacks by Type', data: values, backgroundColor: chartColors, hoverOffset: 4 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } } }); const legendContainer = $('#advaipbl-summary-legend'); legendContainer.empty(); let legendHtml = `<h4>Total Blocked: <strong>${summaryData.total}</strong></h4>`; labels.forEach((label, index) => { const count = values[index]; const color = chartColors[index % chartColors.length]; legendHtml += `<div class="legend-item"><span class="legend-label-group"><span class="legend-color-box" style="background-color: ${color};"></span><span class="legend-label">${label.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span></span><span class="legend-value">${count}</span></div>`; }); legendContainer.html(legendHtml); }
    function renderTimelineWidget(timelineData) { const ctx = document.getElementById('advaipbl-timeline-chart'); if (!ctx || !timelineData) return; new Chart(ctx, { type: 'line', data: { labels: Object.keys(timelineData), datasets: [{ label: 'Blocked Threats', data: Object.values(timelineData), fill: true, borderColor: '#3498db', backgroundColor: 'rgba(52, 152, 219, 0.1)', tension: 0.1 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } }, plugins: { legend: { display: false } } } }); }
    function renderTopLists(topIps, topCountries) { const ipsListContainer = $('#advaipbl-top-ips-list'); const countriesListContainer = $('#advaipbl-top-countries-list'); const attacksLabel = advaipbl_admin_data.text.attacks_label || 'attacks'; const blocksLabel = advaipbl_admin_data.text.blocks_label || 'blocks'; let ipsHtml = '<table>'; if (topIps && topIps.length > 0) { topIps.forEach(item => { ipsHtml += `<tr><td><code>${item.ip}</code></td><td class="count-cell">${item.count} ${attacksLabel}</td></tr>`; }); } else { ipsHtml += '<tr><td>No data available.</td></tr>'; } ipsHtml += '</table>'; ipsListContainer.html(ipsHtml); let countriesHtml = '<table>'; if (topCountries && topCountries.length > 0) { topCountries.forEach(item => { const countryCode = item.country_code ? item.country_code.toLowerCase() : ''; const countryName = item.country || item.country_code || 'Unknown'; let flagHtml = ''; if (countryCode) { const flagUrl = `https://flagcdn.com/w20/${countryCode}.png`; flagHtml = `<img src="${flagUrl}" width="20" height="15" alt="${countryCode.toUpperCase()}" class="country-flag">`; } countriesHtml += `<tr><td class="country-cell">${flagHtml}<span>${countryName}</span></td><td class="count-cell">${item.count} ${blocksLabel}</td></tr>`; }); } else { countriesHtml += '<tr><td>No data available.</td></tr>'; } countriesHtml += '</table>'; countriesListContainer.html(countriesHtml); }

    /**
* Renderiza el widget de estado del sistema.
* @param {object} statusData - Datos del estado de los módulos.
*/
    function renderSystemStatus(statusData) {
        const container = $('#advaipbl-system-status-list');
        if (!container.length || !statusData) return;

        // Actualizamos el mapa de etiquetas para reflejar los nuevos estados.
        const statusMap = {
            'htaccess_firewall': 'Server-Level Firewall (.htaccess)',
            'cloudflare_sync': 'Cloud Edge Defense (Cloudflare)',
            'community_network': 'AIB Community Network',
            'waf': 'Web Application Firewall (WAF)',
            'rate_limit': 'Rate Limiting',
            'spamhaus_asn': 'Spamhaus ASN Protection',
            'manual_asn': 'Manual ASN Protection',
            'geoblock': 'Geoblocking',
            'honeypot': 'Honeypot Protection',
            'user_agent': 'User-Agent Blocking',
            'threat_scoring': 'Threat Scoring System',
            'enable_2fa': 'Two-Factor Authentication (2FA)',
            'signature_logging': 'Signature Logging (Beta)',
            'signature_analysis': 'Signature Analysis (Beta)',
            'signature_blocking': 'Signature Blocking (Beta)',
            'xmlrpc_lockdown': 'XML-RPC Lockdown (Beta)',
            'login_lockdown': 'Login Lockdown (Beta)',
            '404_lockdown': '404 Error Lockdown',
            '404_blocking': '404 Error Blocking',
            '403_lockdown': '403 Error Lockdown',
            '403_blocking': '403 Error Blocking',
            'login_blocking': 'Failed Login Blocking',
            'bot_verification': 'Verify Known Bots',
            'geo_challenge': 'Geo Challenge',
            'abuseipdb': 'AbuseIPDB Protection',
            'activity_audit': 'Activity Audit Log',
            'advanced_rule': 'Advanced Rules'
        };

        let html = '<div class="advaipbl-status-list">';

        // Lógica especial para XML-RPC
        if (typeof statusData.xmlrpc_mode !== 'undefined') {
            const mode = statusData.xmlrpc_mode;
            let icon = 'dashicons-yes-alt advaipbl-status-icon-success';
            let text = 'Smart Protection';
            let tagClass = 'enabled';

            if (mode === 'disabled') {
                text = 'Fully Disabled';
            } else if (mode === 'enabled') {
                text = 'Not Protected';
                icon = 'dashicons-warning advaipbl-status-icon-disabled';
                tagClass = 'disabled';
            }

            html += `
                <div class="advaipbl-status-item">
                    <span class="dashicons ${icon}"></span>
                    <span class="advaipbl-status-label">XML-RPC Protection</span>
                    <span class="advaipbl-status-tag ${tagClass}">${text}</span>
                </div>`;
        }

        // Bucle para el resto de las protecciones
        for (const [key, label] of Object.entries(statusMap)) {
            if (typeof statusData[key] !== 'undefined') {
                const isEnabled = statusData[key];
                const icon = isEnabled ? 'dashicons-yes-alt advaipbl-status-icon-success' : 'dashicons-no-alt advaipbl-status-icon-disabled';
                const text = isEnabled ? 'Enabled' : 'Disabled';
                html += `
                    <div class="advaipbl-status-item">
                        <span class="dashicons ${icon}"></span>
                        <span class="advaipbl-status-label">${label}</span>
                        <span class="advaipbl-status-tag ${isEnabled ? 'enabled' : 'disabled'}">${text}</span>
                    </div>`;
            }
        }
        html += '</div>';
        container.html(html);
    }
    function renderLiveAttackMap(attacksData) {
        const mapWrapper = $('#advaipbl-map-wrapper');
        if (!mapWrapper.length || typeof L === 'undefined') return;

        // Obtenemos el número de IPs del backend a través de los datos del dashboard.
        const blockedCount = (window.advaipbl_admin_data && window.advaipbl_admin_data.counts) ? window.advaipbl_admin_data.counts.blocked : 0;
        const $title = mapWrapper.closest('.advaipbl-dashboard-widget').find('h3');

        // Limpiamos contadores anteriores para evitar duplicados.
        $title.find('.advaipbl-map-counter').remove();

        if (blockedCount > 0) {
            // Usamos las mismas clases que en el resto del plugin y añadimos una clase específica para el mapa.
            // Añadimos también un espacio antes del span para que no se pegue al texto.
            const counterHtml = ` <span class="advaipbl-block-count advaipbl-map-counter">${blockedCount}</span>`;
            $title.append(counterHtml);
        }

        if (!advaipblMapInstance) {
            advaipblMapInstance = L.map('advaipbl-attack-map').setView([20, 0], 2);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 18,
                attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            }).addTo(advaipblMapInstance);
        }

        if (advaipblMarkersLayer) {
            advaipblMarkersLayer.clearLayers();
        } else {
            advaipblMarkersLayer = L.markerClusterGroup();
            advaipblMapInstance.addLayer(advaipblMarkersLayer);
        }

        const pulseIcon = L.divIcon({ className: 'advaipbl-pulse-icon', html: '<div></div>', iconSize: [20, 20], iconAnchor: [10, 10] });

        if (attacksData && attacksData.length > 0) {
            attacksData.forEach(attack => {
                const popupContent = `<b>IP:</b> ${attack.ip}<br><b>Location:</b> ${attack.city}, ${attack.country}<hr style="margin: 5px 0; border-top: 1px solid #ddd;"><b>Type:</b> ${attack.type_display}<br><b>Duration:</b> ${attack.duration_text}`;
                const newMarker = L.marker([attack.lat, attack.lon], { icon: pulseIcon }).bindPopup(popupContent);
                advaipblMarkersLayer.addLayer(newMarker);
            });
        }
        setTimeout(function () {
            if (advaipblMapInstance) {
                advaipblMapInstance.invalidateSize();
            }
        }, 100);
    }

    initDashboard();
});