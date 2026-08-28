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
        renderChallengesOverviewWidget(data.challenge_stats);
        renderAdvancedRulesWidget(data.advanced_rules_stats);
    }

    function renderChallengesOverviewWidget(challengeStats) {
        const ctx = document.getElementById('advaipbl-challenges-chart');
        if (!ctx) return;
        
        let totalServed = 0, totalPassed = 0, totalFailed = 0;
        
        if (challengeStats && Object.keys(challengeStats).length > 0) {
            Object.values(challengeStats).forEach(day => {
                totalServed += (day.served || 0);
                totalPassed += (day.passed || 0);
                totalFailed += (day.failed || 0);
            });
        }
        
        const labels = ['Served', 'Passed', 'Failed'];
        const values = [totalServed, totalPassed, totalFailed];
        const colors = ['#3498db', '#2ecc71', '#e74c3c'];

        new Chart(ctx, { 
            type: 'doughnut', 
            data: { 
                labels: labels, 
                datasets: [{ data: values, backgroundColor: colors, hoverOffset: 4 }] 
            }, 
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { legend: { display: false } } 
            } 
        }); 
        
        const legendContainer = $('#advaipbl-challenges-legend'); 
        legendContainer.empty(); 
        let legendHtml = `<h4>Total Served: <strong>${totalServed}</strong></h4>`; 
        labels.forEach((label, index) => { 
            const count = values[index]; 
            const color = colors[index]; 
            legendHtml += `<div class="legend-item"><span class="legend-label-group"><span class="legend-color-box" style="background-color: ${color};"></span><span class="legend-label">${label}</span></span><span class="legend-value">${count}</span></div>`; 
        }); 
        legendContainer.html(legendHtml);
    }

    function renderAdvancedRulesWidget(rulesStats) {
        const ctx = document.getElementById('advaipbl-advanced-rules-chart');
        if (!ctx || !rulesStats || rulesStats.length === 0) return;

        const labels = rulesStats.map(rule => rule.name);
        const dataHits = rulesStats.map(rule => rule.hits);

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Hits',
                    data: dataHits,
                    backgroundColor: '#9b59b6',
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { beginAtZero: true }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    function renderSummaryWidget(summaryData) { const ctx = document.getElementById('advaipbl-attack-type-chart'); if (!ctx || !summaryData || !summaryData.by_type) return; const labels = Object.keys(summaryData.by_type); const values = Object.values(summaryData.by_type); new Chart(ctx, { type: 'doughnut', data: { labels: labels, datasets: [{ label: 'Attacks by Type', data: values, backgroundColor: chartColors, hoverOffset: 4 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } } }); const legendContainer = $('#advaipbl-summary-legend'); legendContainer.empty(); let legendHtml = `<h4>Total Blocked: <strong>${summaryData.total}</strong></h4>`; labels.forEach((label, index) => { const count = values[index]; const color = chartColors[index % chartColors.length]; legendHtml += `<div class="legend-item"><span class="legend-label-group"><span class="legend-color-box" style="background-color: ${color};"></span><span class="legend-label">${label.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span></span><span class="legend-value">${count}</span></div>`; }); legendContainer.html(legendHtml); }
    function renderTimelineWidget(timelineData) { const ctx = document.getElementById('advaipbl-timeline-chart'); if (!ctx || !timelineData) return; new Chart(ctx, { type: 'line', data: { labels: Object.keys(timelineData), datasets: [{ label: 'Blocked Threats', data: Object.values(timelineData), fill: true, borderColor: '#3498db', backgroundColor: 'rgba(52, 152, 219, 0.1)', tension: 0.1 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } }, plugins: { legend: { display: false } } } }); }
    function renderTopLists(topIps, topCountries) { const ipsListContainer = $('#advaipbl-top-ips-list'); const countriesListContainer = $('#advaipbl-top-countries-list'); const attacksLabel = advaipbl_admin_data.text.attacks_label || 'attacks'; const blocksLabel = advaipbl_admin_data.text.blocks_label || 'blocks'; let ipsHtml = '<table>'; if (topIps && topIps.length > 0) { topIps.forEach(item => { ipsHtml += `<tr><td><code>${item.ip}</code></td><td class="count-cell">${item.count} ${attacksLabel}</td></tr>`; }); } else { ipsHtml += '<tr><td>No data available.</td></tr>'; } ipsHtml += '</table>'; ipsListContainer.html(ipsHtml); let countriesHtml = '<table>'; if (topCountries && topCountries.length > 0) { topCountries.forEach(item => { const countryCode = item.country_code ? item.country_code.toLowerCase() : ''; const countryName = item.country || item.country_code || 'Unknown'; let flagHtml = ''; if (countryCode) { const flagUrl = `https://flagcdn.com/w20/${countryCode}.png`; flagHtml = `<img src="${flagUrl}" width="20" height="15" alt="${countryCode.toUpperCase()}" class="country-flag">`; } countriesHtml += `<tr><td class="country-cell">${flagHtml}<span>${countryName}</span></td><td class="count-cell">${item.count} ${blocksLabel}</td></tr>`; }); } else { countriesHtml += '<tr><td>No data available.</td></tr>'; } countriesHtml += '</table>'; countriesListContainer.html(countriesHtml); }

    /**
     * Renderiza el widget de estado del sistema agrupado.
     * @param {object} statusData - Datos del estado de los mÃ³dulos.
     */
    function renderSystemStatus(statusData) {
        const container = $('#advaipbl-system-status-list');
        if (!container.length || !statusData) return;

        // Mapa de estados agrupados por categorÃ­as lÃ³gicas
        const groupedStatusMap = {
            'Infrastructure & Edge': {
                'cloudflare_sync': 'Cloud Edge Defense',
                'htaccess_firewall': 'Server-Level Firewall',
                'community_network': 'AIB Community Network'
            },
            'Bot & Automated Threats': {
                'bot_verification': 'Verify Known Bots',
                'ai_bot_verification': 'Verify AI Bots (CIDR)',
                'monitoring_bot_verification': 'Verify Monitoring Bots',
                'xmlrpc_lockdown': 'XML-RPC Protection', // LÃ³gica especial inyectada abajo
                'under_attack_mode': 'Auto-Panic Mode'
            },
            'Core Protection Engine': {
                'waf': 'Web Application Firewall',
                'intelligent_waf': 'Zero-Day WAF',
                'honeypot': 'Honeypot Protection',
                'advanced_rule': 'Advanced Rules',
                'cloud_advanced_rules': 'Cloud Advanced Rules Sync',
                'signature_blocking': 'Signature Blocking',
                'block_ghost_ips': 'Block Ghost IPs'
            },
            'Access Control & Thresholds': {
                'geoblock': 'Geoblocking',
                'geo_challenge': 'Geo Challenge',
                'user_agent': 'User-Agent Blocking',
                'spamhaus_asn': 'Spamhaus ASN',
                'manual_asn': 'Manual ASN',
                'rate_limit': 'Rate Limiting',
                '404_blocking': '404 Error Blocking',
                '403_blocking': '403 Error Blocking',
                'login_blocking': 'Failed Login Blocking',
                '404_lockdown': '404 Lockdown',
                '403_lockdown': '403 Lockdown',
                'login_lockdown': 'Login Lockdown',
                'enable_2fa': 'Two-Factor Auth (2FA)'
            },
            'Hardening & Auditing': {
                'abuseipdb': 'AbuseIPDB Protection',
                'threat_scoring': 'Threat Scoring System',
                'signature_analysis': 'Signature Analysis',
                'signature_logging': 'Signature Logging',
                'activity_audit': 'Activity Audit Log',
                'disable_imagick': 'Disable Imagick',
                'hide_wp_version': 'Hide WP Version',
                'disable_app_passwords': 'Disable App Passwords',
                'disable_file_editor': 'Disable File Editor',
                'block_php_uploads': 'Block PHP Uploads',
                'remove_x_powered_by': 'Remove powered by HTTP header',
                'restricted_admins': 'Admin Access Control'
            }
        };

        let html = '<div class="advaipbl-status-list">';

        for (const [groupName, features] of Object.entries(groupedStatusMap)) {
            let groupHtml = '';
            
            for (const [key, label] of Object.entries(features)) {
                // Caso especial para XML-RPC
                if (key === 'xmlrpc_lockdown' && typeof statusData.xmlrpc_mode !== 'undefined') {
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

                    groupHtml += `
                        <div class="advaipbl-status-item">
                            <span class="dashicons ${icon}"></span>
                            <span class="advaipbl-status-label">${label}</span>
                            <span class="advaipbl-status-tag ${tagClass}">${text}</span>
                        </div>`;
                } 
                // Casos estÃ¡ndar
                else if (typeof statusData[key] !== 'undefined') {
                    const isEnabled = statusData[key];
                    const icon = isEnabled ? 'dashicons-yes-alt advaipbl-status-icon-success' : 'dashicons-no-alt advaipbl-status-icon-disabled';
                    const text = isEnabled ? 'Enabled' : 'Disabled';
                    groupHtml += `
                        <div class="advaipbl-status-item">
                            <span class="dashicons ${icon}"></span>
                            <span class="advaipbl-status-label">${label}</span>
                            <span class="advaipbl-status-tag ${isEnabled ? 'enabled' : 'disabled'}">${text}</span>
                        </div>`;
                }
            }

            // Si hay elementos activos en este grupo, aÃ±adimos el encabezado y los elementos
            if (groupHtml !== '') {
                html += `
                    <div class="advaipbl-status-group">
                        <div class="advaipbl-status-group-title">${groupName}</div>
                        ${groupHtml}
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
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
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