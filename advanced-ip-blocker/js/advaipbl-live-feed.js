jQuery(document).ready(function ($) {

    const feedContainer = $('#advaipbl-live-feed-container');
    if (!feedContainer.length) {
        return;
    }

    const feedList = $('#advaipbl-live-feed-list');
    const apiUrl = window.advaipbl_feed_data.api_url || '';
    const feedToken = window.advaipbl_feed_data.token || '';
    const texts = window.advaipbl_feed_data.text || {};

    let lastId = 0;
    let isFetching = false;

    function createFeedItemHtml(attack) {
        let detailsHtml = '<div class="feed-details-grid">';
        detailsHtml += `<div class="feed-label">${texts.type || 'Type'}</div><div class="feed-value"><span class="type-tag">${attack.type}</span></div>`;
        detailsHtml += `<div class="feed-label">${texts.method || 'Method'}</div><div class="feed-value"><code>${attack.method}</code></div>`;
        detailsHtml += `<div class="feed-label">${texts.details || 'Details'}</div><div class="feed-value">${attack.details}</div>`;
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
        if (isFetching || !apiUrl || !feedToken) {
            return;
        }
        isFetching = true;

        const params = new URLSearchParams();
        params.append('token', feedToken);

        if (lastId > 0) {
            params.append('since', lastId);
        }

        const url = `${apiUrl}?${params.toString()}`;

        $.get(url, function (response) {
            if (response && response.attacks && response.attacks.length > 0) {
                feedList.find('.placeholder').remove();
                lastId = response.last_id > lastId ? response.last_id : lastId;
                const newItemsHtml = response.attacks.map(createFeedItemHtml).join('');
                $(newItemsHtml).prependTo(feedList).fadeIn('slow');
                while (feedList.children('li').length > 20) {
                    feedList.children('li').last().remove();
                }
            }
        }).always(function () {
            isFetching = false;
        });
    }

    function initializeFeed() {
        if (!feedToken) {
            console.error('Live Feed: Access token is missing.');
            return;
        }
        
        fetchAttacks();
        setInterval(fetchAttacks, 10000);
    }

    initializeFeed();
});