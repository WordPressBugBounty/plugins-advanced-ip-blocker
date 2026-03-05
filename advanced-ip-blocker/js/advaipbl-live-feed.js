jQuery(document).ready(function($) {

    const feedContainer = $('#advaipbl-live-feed-container');
    if (!feedContainer.length) {
        return;
    }

    const feedList = $('#advaipbl-live-feed-list');
    const apiUrl = window.advaipbl_feed_data.api_url || '';
    const nonceUrl = window.advaipbl_feed_data.nonce_url || '';
    const texts = window.advaipbl_feed_data.text || {};
    
    let lastId = 0;
    let isFetching = false;
    let freshNonce = null; // Almacenaremos el nonce fresco aquí

    function createFeedItemHtml(attack) {
        let detailsHtml = '<div class="feed-details-grid">';
        detailsHtml += `<div class="feed-label">${texts.type || 'Type'}</div><div class="feed-value"><span class="type-tag">${attack.type}</span></div>`;
        detailsHtml += `<div class="feed-label">${texts.method || 'Method'}</div><div class="feed-value"><code>${attack.method}</code></div>`;
        detailsHtml += `<div class="feed-label">${texts.details || 'Details'}</div><div class="feed-value">${attack.details}</div>`;
        if (attack.uri) {
            detailsHtml += `<div class="feed-label">${texts.uri || 'URI'}</div><div class="feed-value"><code>${attack.uri}</code></div>`;
        }
        if (attack.user_agent && attack.user_agent !== 'N/A') {
            detailsHtml += `<div class="feed-label">${texts.user_agent || 'User Agent'}</div><div class="feed-value"><code>${attack.user_agent}</code></div>`;
        }
        detailsHtml += '</div>';
        return `
            <li class="feed-item" style="display:none;">
                <div class="feed-main-line">
                    <span class="ip">${attack.ip}</span>
                    <span class="blocked-text">${texts.blocked_from || 'blocked from'}</span>
                    <span class="location">${attack.location}</span>
                    <span class="time">(${attack.time})</span>
                </div>
                ${detailsHtml}
            </li>
        `;
    }

    function fetchAttacks() {
        if (isFetching || !apiUrl || !freshNonce) {
            return;
        }
        isFetching = true;

        const params = new URLSearchParams();
        params.append('nonce', freshNonce);

        if (lastId > 0) {
            params.append('since', lastId);
        }

        const url = `${apiUrl}?${params.toString()}`;
        
        $.get(url, function(response) {
            if (response && response.attacks && response.attacks.length > 0) {
                feedList.find('.placeholder').remove();
                lastId = response.last_id > lastId ? response.last_id : lastId;
                const newItemsHtml = response.attacks.map(createFeedItemHtml).join('');
                $(newItemsHtml).prependTo(feedList).fadeIn('slow');
                while (feedList.children('li').length > 20) {
                    feedList.children('li').last().remove();
                }
            }
        }).always(function() {
            isFetching = false;
        });
    }
	
    function initializeFeed() {
        if (!nonceUrl) {
            console.error('Live Feed: Nonce URL is missing.');
            return;
        }
        // 1. Primero, obtenemos un nonce fresco que no esté cacheado.
        $.get(nonceUrl, function(response) {
            if (response && response.nonce) {
                freshNonce = response.nonce;
                // 2. Una vez tenemos el nonce, hacemos la primera llamada para obtener datos.
                fetchAttacks();
                // 3. Y ahora programamos las llamadas periódicas.
                setInterval(fetchAttacks, 10000);
            } else {
                console.error('Live Feed: Failed to fetch a valid nonce.');
            }
        }).fail(function() {
            console.error('Live Feed: AJAX error while fetching nonce.');
        });
    }

    initializeFeed();
});