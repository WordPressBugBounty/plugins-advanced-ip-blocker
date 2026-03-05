jQuery(document).ready(function ($) {

    const adminData = window.advaipbl_admin_data || {};
    const showConfirmModal = window.AdvaipblAdmin.showConfirmModal;
    const showAdminNotice = window.AdvaipblAdmin.showAdminNotice;

    /**
     * Maneja la lógica de las acciones masivas (Bulk Actions) de forma robusta.
     */
    function initBulkActions() {
        const form = $('#advaipbl-blocked-ips-form');
        if (!form.length) return;

        const topSelector = form.find('#bulk-action-selector-top');
        const bottomSelector = form.find('#bulk-action-selector-bottom');

        topSelector.on('change', function () {
            bottomSelector.val($(this).val());
        });

        bottomSelector.on('change', function () {
            topSelector.val($(this).val());
        });

        form.find('#cb-select-all-1, #cb-select-all-2').on('click', function () {
            const isChecked = $(this).prop('checked');
            form.find('#the-list input[type="checkbox"][name="ips_to_process[]"]').prop('checked', isChecked);
        });

        form.find('input[type="submit"].action').on('click', function (e) {
            e.preventDefault();

            const isTopButton = $(this).attr('id') === 'doaction';
            const actionSelector = isTopButton ? $('#bulk-action-selector-top') : $('#bulk-action-selector-bottom');
            const action = actionSelector.val();

            if (action === '-1') {
                const alertText = (adminData.text && adminData.text.alert_no_action) ? adminData.text.alert_no_action : 'Please select a bulk action.';
                alert(alertText);
                return;
            }

            if (action === 'unblock_all') {
                showConfirmModal({
                    title: 'Confirm Mass Unblock',
                    message: 'Are you sure you want to unblock ALL IPs from ALL blocklists? This action cannot be undone.',
                    confirmText: 'Yes, Unblock All IPs',
                    onConfirm: function () {
                        form.find('select[name="bulk_action"], select[name="bulk_action2"]').val(action);
                        form.submit();
                    }
                });
            } else if (action === 'unblock') {
                const checkedItems = form.find('#the-list input[type="checkbox"][name="ips_to_process[]"]:checked');
                if (checkedItems.length === 0) {
                    const alertItemsText = (adminData.text && adminData.text.alert_no_items) ? adminData.text.alert_no_items : 'Please select at least one item to apply the action.';
                    alert(alertItemsText);
                    return;
                }
                showConfirmModal({
                    title: (adminData.text && adminData.text.confirm_bulk_action_title) ? adminData.text.confirm_bulk_action_title : 'Confirm Bulk Action',
                    message: ((adminData.text && adminData.text.confirm_bulk_unblock_message) ? adminData.text.confirm_bulk_unblock_message : 'Are you sure you want to unblock the selected %d entries?').replace('%d', checkedItems.length),
                    confirmText: (adminData.text && adminData.text.confirm_bulk_unblock_button) ? adminData.text.confirm_bulk_unblock_button : 'Yes, Unblock Selected',
                    onConfirm: function () {
                        form.find('select[name="bulk_action"], select[name="bulk_action2"]').val(action);
                        form.submit();
                    }
                });
            }
        });
    }

    /**
     * Maneja la lógica de las acciones masivas para la tabla de la Whitelist.
     */
    function initWhitelistBulkActions() {
        const form = $('#advaipbl-whitelist-form');
        if (!form.length) return;

        // Lógica para los checkboxes "seleccionar todo"
        form.find('#cb-select-all-1').on('click', function () {
            const isChecked = $(this).prop('checked');
            form.find('#the-list input[type="checkbox"][name="entries_to_process[]"]').prop('checked', isChecked);
        });

        // Lógica para los botones "Apply"
        form.find('input[type="submit"].action').on('click', function (e) {
            e.preventDefault();

            const isTopButton = $(this).attr('id') === 'doaction';
            const actionSelector = isTopButton ? $('#bulk-action-selector-top') : $('#bulk-action-selector-bottom');
            const action = actionSelector.val();

            if (action === '-1') {
                const alertText = (adminData.text && adminData.text.alert_no_action) ? adminData.text.alert_no_action : 'Please select a bulk action.';
                alert(alertText);
                return;
            }

            const checkedItems = form.find('#the-list input[type="checkbox"][name="entries_to_process[]"]:checked');
            if (checkedItems.length === 0) {
                const alertItemsText = (adminData.text && adminData.text.alert_no_items) ? adminData.text.alert_no_items : 'Please select at least one item to apply the action.';
                alert(alertItemsText);
                return;
            }

            if (action === 'remove') {
                showConfirmModal({
                    title: 'Confirm Removal',
                    message: ((adminData.text && adminData.text.confirm_bulk_whitelist_remove_message) ? adminData.text.confirm_bulk_whitelist_remove_message : 'Are you sure you want to remove the selected %d entries from the whitelist?').replace('%d', checkedItems.length),
                    confirmText: 'Yes, Remove Selected',
                    onConfirm: function () {
                        // Asegurarse de que ambos selectores tienen el valor correcto antes de enviar
                        form.find('select[name="bulk_action"], select[name="bulk_action2"]').val(action);
                        form.submit();
                    }
                });
            }
        });
    }

    /**
    * Maneja el cambio de los filtros de la tabla de IPs Bloqueadas para recargar la página.
    */
    function initBlockedIpsFilters() {
        // Seleccionamos los filtros que NO están dentro del formulario de acciones masivas
        $('#filter-by-type, .advaipbl-per-page-selector').not('#advaipbl-blocked-ips-form .advaipbl-per-page-selector').on('change', function () {
            let currentUrl = window.location.href.split('?')[0];
            let params = new URLSearchParams(window.location.search);
            const val = $('#filter-by-type').val();
            if (val) {
                params.set('filter_type', val);
            }
            params.set('advaipbl_per_page', $('.advaipbl-per-page-selector').val());
            params.set('paged', 1);
            window.location.href = currentUrl + '?' + params.toString();
        });
    }

    /**
     * Adjunta las advertencias de seguridad a todos los selectores de países (Geoblock y Geo-Challenge).
     */
    function attachGeoblockWarning() {
        if (typeof adminData.geoblock === 'undefined') return;

        // Iteramos sobre cada selector de país que tengamos en la página
        $('.advaipbl-country-select').each(function () {
            const $selector = $(this);
            const selectorId = $selector.attr('id');
            const isChallengeSelector = selectorId === 'advaipbl_geo_challenge_countries';

            const data = adminData.geoblock;
            const server = data.server || {};
            const admin = data.admin || {};
            const texts = adminData.text || {};

            const countryList = isChallengeSelector ? (data.challenged_countries || []) : (data.blocked_countries || []);

            const warningContainer = $('<div class="advaipbl-geoblock-warnings"></div>');
            $selector.parent().append(warningContainer);

            const checkAndDisplayWarnings = function () {
                const selectedCountries = $selector.val() || [];
                warningContainer.empty().hide();

                const serverCountrySelected = server.country_code && selectedCountries.includes(server.country_code);
                const isAdminCountrySelected = admin.country_code && selectedCountries.includes(admin.country_code);

                const createButtonHtml = (ip, detail) => ` <button class="button button-secondary advaipbl-add-whitelist-ajax" data-ip="${ip}" data-detail="${detail}">${texts.add_to_whitelist_btn}</button>`;

                let serverMessageHtml = '';
                if (serverCountrySelected && server.ip) {
                    const serverText = server.is_whitelisted ? texts.server_whitelisted : texts.server_not_whitelisted;
                    const serverType = server.is_whitelisted ? 'info' : 'error';
                    const serverButton = server.is_whitelisted ? '' : createButtonHtml(server.ip, 'Server IP (auto-added via warning)');
                    const formattedText = serverText.replace('%1$s', `<strong>${server.country_name || server.country_code}</strong>`).replace('%2$s', `<code>${server.ip}</code>`);
                    serverMessageHtml = `<div class="advaipbl-notice advaipbl-notice-${serverType}"><p>${formattedText}${serverButton}</p></div>`;
                }

                let adminMessageHtml = '';
                if (isAdminCountrySelected && admin.ip && admin.ip !== server.ip) {
                    const adminText = admin.is_whitelisted ? texts.admin_whitelisted : texts.admin_not_whitelisted;
                    const adminType = admin.is_whitelisted ? 'info' : 'warning';
                    const adminButton = admin.is_whitelisted ? '' : createButtonHtml(admin.ip, 'Admin IP (auto-added via warning)');
                    const formattedText = adminText.replace('%1$s', `<code>${admin.ip}</code>`).replace('%2$s', `<strong>${admin.country_name || admin.country_code}</strong>`);
                    adminMessageHtml = `<div class="advaipbl-notice advaipbl-notice-${adminType}"><p>${formattedText}${adminButton}</p></div>`;
                }

                if (serverMessageHtml || adminMessageHtml) {
                    warningContainer.append(serverMessageHtml).append(adminMessageHtml).slideDown('fast');
                }
            };

            $selector.on('change', checkAndDisplayWarnings);
            checkAndDisplayWarnings(); // Ejecutar al cargar la página
        });
    }

    function attachWhitelistRemoveWarning() {
        $('body').on('click', '.advaipbl-remove-whitelist-button', function (e) {
            e.preventDefault();
            const form = $(this).closest('form');
            if (typeof adminData.geoblock === 'undefined') { form.get(0).submit(); return; }

            const ipToRemove = $(this).data('ip-to-remove');
            const data = adminData.geoblock;
            const server = data.server || {};
            const admin = data.admin || {};
            const blockedCountries = data.blocked_countries || [];
            const texts = adminData.text || {};

            let warningMessage = '';

            if (server.ip === ipToRemove && server.country_code && blockedCountries.includes(server.country_code)) {
                warningMessage += texts.remove_server_ip_warning.replace('%1$s', `<strong>${server.ip}</strong>`).replace('%2$s', `<strong>${server.country_name}</strong>`) + '<br><br>';
            }
            if (admin.ip === ipToRemove && admin.country_code && blockedCountries.includes(admin.country_code)) {
                warningMessage += texts.remove_admin_ip_warning.replace('%1$s', `<strong>${admin.ip}</strong>`).replace('%2$s', `<strong>${admin.country_name || admin.country_code}</strong>`) + '<br><br>';
            }

            if (warningMessage) {
                warningMessage += texts.confirm_removal;
                showConfirmModal({
                    title: 'Confirmation Required',
                    message: warningMessage,
                    confirmText: 'Yes, Proceed',
                    onConfirm: function () {
                        form.get(0).submit();
                    }
                });
            } else {
                form.get(0).submit();
            }
        });
    }

    function initWhitelistAjaxButton() {
        $('body').on('click', '.advaipbl-add-whitelist-ajax', function (e) {
            e.preventDefault();
            const $button = $(this);
            const ip = $button.data('ip');
            const detail = $button.data('detail');
            const originalText = $button.html();
            const texts = adminData.text || {};

            $button.text(texts.adding_to_whitelist).prop('disabled', true);

            $.post(ajaxurl, {
                action: 'advaipbl_add_ip_to_whitelist',
                nonce: adminData.nonces.add_whitelist,
                ip: ip,
                detail: detail
            }).done(function (response) {
                if (response.success) {
                    const successHtml = `<span class="advaipbl-status-icon success" title="${response.data.message}">✔ ${texts.added_to_whitelist}</span>`;
                    const $notice = $button.closest('.advaipbl-notice');
                    $button.replaceWith(successHtml);
                    if ($notice.length) {
                        $notice.removeClass('advaipbl-notice-error advaipbl-notice-warning').addClass('advaipbl-notice-info');
                    }
                } else {
                    $button.html(originalText).prop('disabled', false);
                    showAdminNotice('Error: ' + response.data.message, 'error');
                }
            }).fail(function () {
                $button.html(originalText).prop('disabled', false);
                showAdminNotice(texts.ajax_error, 'error');
            });
        });
    }

    function initPerPageSelector() {
        $('body').on('change', '.advaipbl-per-page-selector', function () {
            const $form = $(this).closest('form');
            if ($form.length) {
                $form.get(0).submit();
            }
        });
    }

    function initCountrySelectors() {
        if (typeof $.fn.select2 !== 'function') return;
        $('.advaipbl-country-select').each(function () {
            const $selector = $(this);
            const placeholder = $selector.data('placeholder') || 'Search for a country...';
            $selector.select2({ placeholder: placeholder, width: '100%', maximumSelectionLength: 100 });
        });
    }

    function initializeAdvancedRules() {
        const rulesListContainer = $('#advaipbl-advanced-rules-list');
        const navContainers = $('.advaipbl-rules-nav-bar');
        if (!rulesListContainer.length) { return; }

        const modal = $('#advaipbl-rule-builder-modal');
        const conditionTemplate = $('#advaipbl-condition-template').html();
        const conditionsContainer = $('#advaipbl-rule-conditions');

        const operators = {
            string: [{ value: 'is', text: 'is' }, { value: 'is_not', text: 'is not' }, { value: 'contains', text: 'contains' }, { value: 'does_not_contain', text: 'does not contain' }, { value: 'starts_with', text: 'starts with' }, { value: 'ends_with', text: 'ends with' }, { value: 'matches_regex', text: 'matches regex' }],
            ip: [{ value: 'is', text: 'is' }, { value: 'is_not', text: 'is not' }],
            ip_range: [{ value: 'is', text: 'is in range' }, { value: 'is_not', text: 'is not in range' }]
        };

        function updateOperatorDropdown(conditionRow) {
            const type = conditionRow.find('.condition-type').val();
            const operatorDropdown = conditionRow.find('.condition-operator');
            let ops = [...operators.string];
            if (type === 'ip') ops = [...operators.ip];
            if (type === 'ip_range' || type === 'country' || type === 'asn') ops = [...operators.ip_range];
            if (type === 'country' || type === 'asn') {
                const isOp = ops.find(op => op.value === 'is'); if (isOp) isOp.text = 'is';
                const isNotOp = ops.find(op => op.value === 'is_not'); if (isNotOp) isNotOp.text = 'is not';
            }
            operatorDropdown.empty();
            ops.forEach(op => operatorDropdown.append($('<option>', { value: op.value, text: op.text })));
        }

        function updateValueInput(conditionRow) {
            const type = conditionRow.find('.condition-type').val();
            const valueContainer = conditionRow.find('.condition-value-container');
            valueContainer.empty();
            if (type === 'country') {
                const select = $('<select>', { class: 'condition-value', style: 'width: 100%;' });
                select.append(new Option('', '', false, false));
                if (adminData.countries) {
                    for (const [code, name] of Object.entries(adminData.countries)) {
                        select.append(new Option(name, code, false, false));
                    }
                }
                valueContainer.append(select);
                select.select2({ dropdownParent: modal, placeholder: 'Search for a country...', closeOnSelect: true });
            } else {
                let placeholder = 'e.g., /admin/login.php';
                if (type === 'ip') placeholder = 'e.g., 1.2.3.4';
                if (type === 'ip_range') placeholder = 'e.g., 1.2.3.0/24';
                if (type === 'asn') placeholder = 'e.g., AS15169';
                if (type === 'user_agent') placeholder = 'e.g., BadBot/1.0';
                if (type === 'username') placeholder = 'e.g., admin';
                valueContainer.append($('<input>', { type: 'text', class: 'condition-value', placeholder: placeholder }));
            }
        }

        function addConditionRow(condition = {}) {
            const newRow = $(conditionTemplate);
            conditionsContainer.append(newRow);
            updateOperatorDropdown(newRow);
            updateValueInput(newRow);
            if (condition.type) {
                newRow.find('.condition-type').val(condition.type);
                updateOperatorDropdown(newRow);
                updateValueInput(newRow);
                newRow.find('.condition-operator').val(condition.operator);
                if (condition.type === 'country') {
                    newRow.find('.condition-value').val(condition.value).trigger('change');
                } else {
                    newRow.find('.condition-value').val(condition.value);
                }
            }
        }

        function updateActionParams() {
            const action = $('#advaipbl-rule-action').val();
            const paramsContainer = $('#advaipbl-rule-action-params');
            paramsContainer.empty();
            $('#advaipbl-rule-action-params-row').show();
            if (action === 'block') {
                paramsContainer.html('<input type="number" id="param-duration" class="small-text" min="0"> minutes. <span class="description">(Set to 0 for a permanent block)</span>');
            } else if (action === 'score') {
                paramsContainer.html('<input type="number" id="param-points" class="small-text" min="1" value="10"> points.');
            } else {
                $('#advaipbl-rule-action-params-row').hide();
            }
        }

        function renderRule(rule) {
            let conditionsHtml = rule.conditions.map(c => `<li><span class="rule-component-type">${c.type.replace('_', ' ')}</span> <span class="rule-component-operator">${c.operator.replace('_', ' ')}</span> <code class="rule-component-value">${c.value}</code></li>`).join('');
            let actionHtml = `<span class="rule-action-type" data-action="${rule.action}">${rule.action}</span>`;
            if (rule.action_params) {
                if (rule.action_params.duration !== undefined) actionHtml += ` <span class="rule-action-param">(${rule.action_params.duration > 0 ? rule.action_params.duration + ' min' : 'permanent'})</span>`;
                if (rule.action_params.points) actionHtml += ` <span class="rule-action-param">(+${rule.action_params.points} pts)</span>`;
            }

            return `
        <div class="advaipbl-rule-card" data-rule-id="${rule.id}">
            <div class="rule-selector"><input type="checkbox" class="rule-checkbox"></div>
            <div class="rule-name"><strong>${rule.name}</strong></div>
            <div class="rule-summary">
                <strong>IF:</strong> ${conditionsHtml}
            </div>
            <div class="rule-action">
                <strong>THEN:</strong> ${actionHtml}
            </div>
            <div class="rule-actions">
                <button class="button button-secondary move-rule-up" title="Move Up"><span class="dashicons dashicons-arrow-up-alt2"></span></button>
                <button class="button button-secondary move-rule-down" title="Move Down"><span class="dashicons dashicons-arrow-down-alt2"></span></button>
                <button class="button button-secondary edit-rule">Edit</button>
                <button class="button button-link-delete delete-rule">Delete</button>
            </div>
        </div>`;
        }

        function renderPagination(pagination) {
            const paginationContainers = $('.advaipbl-pagination-container');
            paginationContainers.empty();
            if (pagination.total_pages <= 1) {
                if (pagination.total_items > 0) {
                    paginationContainers.html(`<div class="tablenav-pages one-page"><span class="displaying-num">${pagination.total_items} items</span></div>`);
                }
                return;
            }
            const paginationHtml = `<div class="tablenav-pages"><span class="displaying-num">${pagination.total_items} items</span><span class="pagination-links"><a class="prev-page button ${pagination.current_page <= 1 ? 'disabled' : ''}" href="#" data-page="${pagination.current_page - 1}">‹</a><span class="screen-reader-text">Current Page</span><span class="paging-input"><span class="tablenav-paging-text">${pagination.current_page} of <span class="total-pages">${pagination.total_pages}</span></span></span><a class="next-page button ${pagination.current_page >= pagination.total_pages ? 'disabled' : ''}" href="#" data-page="${pagination.current_page + 1}">›</a></span></div>`;
            paginationContainers.html(paginationHtml);
        }

        function loadRules(page = 1) {
            rulesListContainer.html('<div class="advaipbl-loader-wrapper"><div class="advaipbl-loader"></div></div>');
            navContainers.hide();
            $.post(ajaxurl, {
                action: 'advaipbl_get_advanced_rules',
                nonce: adminData.nonces.get_rules_nonce,
                page: page
            }).done(function (response) {
                rulesListContainer.empty();
                if (response.success) {
                    if (response.data.rules && response.data.rules.length > 0) {
                        navContainers.show();
                        response.data.rules.forEach(rule => { rulesListContainer.append(renderRule(rule)); });
                        renderPagination(response.data.pagination);
                    } else {
                        rulesListContainer.html(`<p>${adminData.text.no_advanced_rules || 'No advanced rules have been created yet.'}</p>`);
                    }
                } else {
                    rulesListContainer.html(`<p class="error">${adminData.text.could_not_load_rules || 'Could not load rules.'}</p>`);
                }
            }).fail(function () {
                navContainers.hide();
                rulesListContainer.html(`<p class="error">${adminData.text.ajax_error || 'An AJAX error occurred.'}</p>`);
            });
        }

        $('#advaipbl-add-new-rule-btn').on('click', function () { modal.find('.advaipbl-modal-title').text('Add New Rule'); $('#advaipbl-rule-id').val(''); $('#advaipbl-rule-name').val(''); conditionsContainer.empty(); addConditionRow(); updateActionParams(); modal.show(); });
        modal.on('click', '.advaipbl-modal-cancel', function () { modal.hide(); });
        conditionsContainer.on('change', '.condition-type', function () { const row = $(this).closest('.advaipbl-condition-row'); updateOperatorDropdown(row); updateValueInput(row); });
        conditionsContainer.on('click', '.remove-condition', function () { $(this).closest('.advaipbl-condition-row').remove(); });
        $('#advaipbl-add-condition-btn').on('click', addConditionRow);
        $('#advaipbl-rule-action').on('change', updateActionParams);

        $('#advaipbl-save-rule-btn').on('click', function () { const button = $(this); button.prop('disabled', true); const feedback = $('#advaipbl-rule-builder-feedback'); feedback.text('Saving...').css('color', ''); const rule = { id: $('#advaipbl-rule-id').val(), name: $('#advaipbl-rule-name').val().trim(), conditions: [], action: $('#advaipbl-rule-action').val(), action_params: {} }; if (!rule.name) { feedback.text('Rule name is required.').css('color', 'red'); button.prop('disabled', false); return; } conditionsContainer.find('.advaipbl-condition-row').each(function () { const row = $(this); rule.conditions.push({ type: row.find('.condition-type').val(), operator: row.find('.condition-operator').val(), value: row.find('.condition-value').val() }); }); if (rule.action === 'block') rule.action_params.duration = parseInt($('#param-duration').val()) || 0; if (rule.action === 'score') rule.action_params.points = parseInt($('#param-points').val()) || 10; $.post(ajaxurl, { action: 'advaipbl_save_advanced_rule', nonce: adminData.nonces.save_rule_nonce, rule: JSON.stringify(rule) }).done(function (response) { if (response.success) { feedback.text(response.data.message).css('color', 'green'); setTimeout(() => { modal.hide(); loadRules(); }, 1000); } else { feedback.text(response.data.message).css('color', 'red'); } }).fail(function () { feedback.text('An AJAX error occurred.').css('color', 'red'); }).always(function () { button.prop('disabled', false); }); });
        rulesListContainer.on('click', '.delete-rule', function (e) {
            e.preventDefault();
            const card = $(this).closest('.advaipbl-rule-card');
            const ruleId = card.data('rule-id');
            const ruleName = card.find('.rule-name strong').text();
            showConfirmModal({
                title: adminData.text.delete_rule_confirm_title || 'Delete Rule?',
                message: (adminData.text.delete_rule_confirm_message || 'Are you sure you want to permanently delete the rule "%s"?').replace('%s', `<strong>${ruleName}</strong>`),
                confirmText: adminData.text.delete_rule_confirm_button || 'Yes, Delete Rule',
                onConfirm: function () {
                    card.css('opacity', '0.5');
                    $.post(ajaxurl, { action: 'advaipbl_delete_advanced_rule', nonce: adminData.nonces.delete_rule_nonce, rule_id: ruleId }).done(function (response) { if (response.success) { loadRules(1); showAdminNotice(response.data.message, 'success'); } else { showAdminNotice(response.data.message || 'Error.', 'error'); card.css('opacity', '1'); } }).fail(function () { showAdminNotice(adminData.text.ajax_error, 'error'); card.css('opacity', '1'); });
                }
            });
        });
        rulesListContainer.on('click', '.edit-rule', function () { const card = $(this).closest('.advaipbl-rule-card'); const ruleId = card.data('rule-id'); $.post(ajaxurl, { action: 'advaipbl_get_advanced_rules', nonce: adminData.nonces.get_rules_nonce }, function (response) { if (response.success) { const ruleToEdit = response.data.rules.find(r => r.id === ruleId); if (ruleToEdit) { $('#advaipbl-rule-id').val(ruleToEdit.id); $('#advaipbl-rule-name').val(ruleToEdit.name); conditionsContainer.empty(); ruleToEdit.conditions.forEach(c => addConditionRow(c)); $('#advaipbl-rule-action').val(ruleToEdit.action); updateActionParams(); if (ruleToEdit.action === 'block') $('#param-duration').val(ruleToEdit.action_params.duration); if (ruleToEdit.action === 'score') $('#param-points').val(ruleToEdit.action_params.points); modal.find('.advaipbl-modal-title').text('Edit Rule'); modal.show(); } } }); });
        $('.advaipbl-rules-nav-bar').on('click', 'a.prev-page, a.next-page', function (e) { e.preventDefault(); if ($(this).hasClass('disabled')) return; const page = $(this).data('page'); loadRules(page); });

        const navs = $('.advaipbl-rules-nav-bar');
        const topBulkSelector = navs.first().find('.advaipbl-adv-rules-bulk-action');
        const bottomBulkSelector = navs.last().find('.advaipbl-adv-rules-bulk-action');
        topBulkSelector.on('change', () => bottomBulkSelector.val(topBulkSelector.val()));
        bottomBulkSelector.on('change', () => topBulkSelector.val(topBulkSelector.val()));
        navs.on('click', '.advaipbl-apply-bulk-action', function () {
            const action = $(this).siblings('select').val();
            if (action === '-1') { alert('Please select a bulk action.'); return; }
            const selected_ids = [];
            rulesListContainer.find('.rule-checkbox:checked').each(function () { selected_ids.push($(this).closest('.advaipbl-rule-card').data('rule-id')); });
            if (selected_ids.length === 0) { alert('Please select at least one rule.'); return; }
            if (action === 'delete') {
                showConfirmModal({
                    title: 'Confirm Bulk Deletion',
                    message: `Are you sure you want to delete the selected ${selected_ids.length} rule(s)?`,
                    confirmText: 'Yes, Delete Selected',
                    onConfirm: function () {
                        $.post(ajaxurl, { action: 'advaipbl_bulk_delete_advanced_rules', nonce: adminData.nonces.bulk_delete_rules_nonce, rule_ids: selected_ids }).done(function (response) { if (response.success) { showAdminNotice(response.data.message, 'success'); loadRules(1); } else { showAdminNotice(response.data.message, 'error'); } });
                    }
                });
            }
        });
        const selectAllTop = $('<input type="checkbox" class="advaipbl-rule-select-all">');
        const selectAllBottom = $('<input type="checkbox" class="advaipbl-rule-select-all">');
        navs.first().find('.bulkactions').prepend(selectAllTop);
        navs.last().find('.bulkactions').prepend(selectAllBottom);
        selectAllTop.add(selectAllBottom).on('change', function () { const isChecked = $(this).prop('checked'); selectAllTop.prop('checked', isChecked); selectAllBottom.prop('checked', isChecked); rulesListContainer.find('.rule-checkbox').prop('checked', isChecked); });

        rulesListContainer.off('click', '.move-rule-up').on('click', '.move-rule-up', function () { moveRule($(this).closest('.advaipbl-rule-card').data('rule-id'), 'up'); });
        rulesListContainer.off('click', '.move-rule-down').on('click', '.move-rule-down', function () { moveRule($(this).closest('.advaipbl-rule-card').data('rule-id'), 'down'); });

        function moveRule(ruleId, direction) {
            $.post(ajaxurl, { action: 'advaipbl_reorder_rules', nonce: adminData.nonces.reorder_rules_nonce, rule_id: ruleId, direction: direction }).done(function (response) { if (response.success) { const currentPage = parseInt($('.advaipbl-rules-nav-bar .paging-input .tablenav-paging-text').text().split(' ')[0]) || 1; loadRules(currentPage); } else { showAdminNotice(response.data.message || 'Error reordering rules.', 'error'); } }).fail(function () { showAdminNotice(adminData.text.ajax_error, 'error'); });
        }

        loadRules();
    }

    // Initialize Rules Logic
    initBulkActions();
    initWhitelistBulkActions();
    initBlockedIpsFilters();
    attachGeoblockWarning();
    attachWhitelistRemoveWarning();
    initWhitelistAjaxButton();
    initPerPageSelector();
    initCountrySelectors();
    initializeAdvancedRules();
    initEndpointLockdownActions();

    function initEndpointLockdownActions() {
        const $body = $('body');
        $body.on('click', '.advaipbl-delete-lockdown', function (e) {
            e.preventDefault();
            const $button = $(this);
            const url = $button.attr('href');
            const endpointName = $button.closest('tr').find('td:first-child code').text();
            showConfirmModal({
                title: 'Cancel Lockdown?',
                message: `Are you sure you want to cancel the lockdown for the <strong>${endpointName}</strong> endpoint?`,
                confirmText: 'Yes, Cancel Lockdown',
                onConfirm: function () { window.location.href = url; }
            });
        });

        const modal = $('#advaipbl-lockdown-details-modal');
        $body.on('click', '.advaipbl-view-lockdown-details', function (e) {
            e.preventDefault();
            const lockdownId = $(this).closest('tr').data('lockdown-id');
            const endpointName = $(this).closest('tr').find('td:first-child code').text();
            modal.find('.advaipbl-modal-title').html(`Lockdown Details: <code>${endpointName}</code>`);
            modal.find('.details-content').hide().empty();
            modal.find('.advaipbl-loader-wrapper').show();
            modal.fadeIn('fast');

            $.post(ajaxurl, { action: 'advaipbl_get_lockdown_details', nonce: adminData.nonces.get_lockdown_details, id: lockdownId }).done(function (response) {
                if (response.success && response.data.details) {
                    const details = response.data.details;
                    const ipDetails = details.details ? JSON.parse(details.details) : {};
                    let detailsHtml = `<h4>${details.reason}</h4><p>Triggering IP Hashes:</p>`;
                    if (ipDetails.triggering_ip_hashes && ipDetails.triggering_ip_hashes.length > 0) {
                        detailsHtml += '<ul class="ul-disc">' + ipDetails.triggering_ip_hashes.map(hash => `<li><code>${hash.substring(0, 12)}...</code></li>`).join('') + '</ul>';
                    } else { detailsHtml += '<p>No specific triggering IP hashes recorded.</p>'; }

                    if (ipDetails.samples && ipDetails.samples.length > 0) {
                        detailsHtml += '<hr><h5>Recent Attack Samples</h5><div style="max-height: 250px; overflow-y: auto;"><table class="widefat striped"><thead><tr><th>Time</th><th>URI</th><th>UA</th></tr></thead><tbody>';
                        ipDetails.samples.forEach(sample => {
                            const time = sample.time || 'N/A';
                            const uri = $('<div>').text(sample.uri).html();
                            const ua = $('<div>').text(sample.ua).html();
                            detailsHtml += `<tr><td>${time}</td><td><code>${uri}</code></td><td style="font-size:11px;">${ua}</td></tr>`;
                        });
                        detailsHtml += '</tbody></table></div>';
                    }
                    modal.find('.details-content').html(detailsHtml);
                } else { modal.find('.details-content').html(`<p>${response.data.message || 'Error.'}</p>`); }
            }).fail(function () { modal.find('.details-content').html('<p>AJAX error.</p>'); }).always(function () { modal.find('.advaipbl-loader-wrapper').hide(); modal.find('.details-content').show(); });
        });
        modal.find('.advaipbl-modal-cancel').on('click', function () { modal.fadeOut('fast'); });
    }

    function initBulkImportExport() {
        const importBtn = $('#advaipbl-bulk-import-btn');
        const exportBtn = $('#advaipbl-bulk-export-btn');
        const modal = $('#advaipbl-bulk-import-modal');
        const processBtn = $('#advaipbl-process-bulk-import');
        const resultsDiv = $('#advaipbl-bulk-import-results');
        const detailInput = $('#advaipbl-bulk-import-detail');
        const textarea = $('#advaipbl-bulk-import-textarea');

        if (importBtn.length) {
            // Open Import Modal
            importBtn.on('click', function (e) {
                e.preventDefault();
                modal.fadeIn('fast');
                textarea.val('');
                detailInput.val('');
                resultsDiv.hide().empty();
            });

            // Close Modal
            modal.on('click', '.advaipbl-modal-cancel', function () {
                modal.fadeOut('fast');
            });

            // Process Import
            processBtn.on('click', function (e) {
                e.preventDefault();
                const ipList = textarea.val().trim();
                const detail = detailInput.val().trim();

                if (!ipList) {
                    alert('Please enter at least one IP address.');
                    return;
                }
                if (!detail) {
                    // Use localized string or fallback
                    const errorMsg = (adminData.text && adminData.text.missing_detail) ? adminData.text.missing_detail : 'Please provide a reason/detail for these IPs (Required).';
                    resultsDiv.html('<div class="notice notice-error inline"><p>' + errorMsg + '</p></div>').show();
                    // Optionally highlight the input
                    detailInput.css('border-color', '#d63638');
                    return;
                } else {
                    // Reset border if valid
                    detailInput.css('border-color', '');
                }

                processBtn.prop('disabled', true).text('Processing...');
                resultsDiv.hide().empty();

                $.post(ajaxurl, {
                    action: 'advaipbl_bulk_import_whitelist',
                    nonce: adminData.nonces.bulk_import_nonce, // We need to ensure this nonce is passed from PHP
                    ip_list: ipList,
                    detail: detail
                }).done(function (response) {
                    if (response.success) {
                        const msgClass = response.data.skipped > 0 ? 'notice-warning' : 'notice-success';
                        const resultsHtml = `<div class="notice ${msgClass} inline"><p>${response.data.message}</p></div>`;
                        resultsDiv.html(resultsHtml).show();
                        if (response.data.imported > 0) {
                            // Reload after a short delay to show the success message
                            setTimeout(function () {
                                location.reload();
                            }, 2000);
                        }
                    } else {
                        resultsDiv.html(`<div class="notice notice-error inline"><p>${response.data.message}</p></div>`).show();
                    }
                }).fail(function () {
                    resultsDiv.html('<div class="notice notice-error inline"><p>System error occurred during import.</p></div>').show();
                }).always(function () {
                    processBtn.prop('disabled', false).text('Import IPs');
                });
            });

            // Export Logic
            exportBtn.on('click', function (e) {
                e.preventDefault();
                const originalText = exportBtn.text();
                exportBtn.prop('disabled', true).text('Generating...');

                $.post(ajaxurl, {
                    action: 'advaipbl_bulk_export_whitelist',
                    nonce: adminData.nonces.bulk_export_nonce, // Ensure nonce exists
                    include_details: false // Default to simple text list as agreed
                }).done(function (response) {
                    if (response.success) {
                        // Create a hidden link to trigger download
                        const link = document.createElement('a');
                        link.href = response.data.file_url;
                        link.download = response.data.filename;
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                    } else {
                        alert(response.data.message || 'Export failed.');
                    }
                }).fail(function () {
                    alert('System error occurred during export.');
                }).always(function () {
                    exportBtn.prop('disabled', false).text(originalText);
                });
            });
        }

        const importBlockedBtn = $('#advaipbl-bulk-import-blocked-btn');
        const exportBlockedBtn = $('#advaipbl-bulk-export-blocked-btn');
        const modalBlocked = $('#advaipbl-bulk-import-blocked-modal');
        const processBlockedBtn = $('#advaipbl-process-bulk-import-blocked');
        const resultsBlockedDiv = $('#advaipbl-bulk-import-blocked-results');
        const textareaBlocked = $('#advaipbl-bulk-import-blocked-textarea');
        const durationBlockedSelect = $('#advaipbl-bulk-import-blocked-duration');
        const csvFileInput = $('#advaipbl-bulk-import-blocked-csv');
        const csvFileNameDisplay = $('#advaipbl-bulk-import-blocked-csv-name');

        if (importBlockedBtn.length) {
            importBlockedBtn.on('click', function (e) {
                e.preventDefault();
                modalBlocked.fadeIn('fast');
                textareaBlocked.val('');
                durationBlockedSelect.val('1440'); // Default to 24 Hours
                csvFileInput.val('');
                csvFileNameDisplay.text('');
                resultsBlockedDiv.hide().empty();
            });

            // Handle CSV File Selection
            csvFileInput.on('change', function (e) {
                const file = e.target.files[0];
                if (!file) {
                    csvFileNameDisplay.text('');
                    return;
                }

                csvFileNameDisplay.text(file.name);

                const reader = new FileReader();
                reader.onload = function (e) {
                    const contents = e.target.result;
                    let ips = [];
                    // Basic CSV parsing: split by newlines, take first column assuming IP is there
                    const lines = contents.split(/\r\n|\n/);
                    lines.forEach(line => {
                        const parts = line.split(',');
                        if (parts[0]) {
                            // Clean up quotes if present
                            ips.push(parts[0].replace(/['"]/g, '').trim());
                        }
                    });

                    if (ips.length > 0) {
                        // Append to textarea (or replace depending on preference, here we replace for simplicity)
                        textareaBlocked.val(ips.join('\n'));
                    }
                };
                reader.readAsText(file);
            });

            modalBlocked.on('click', '.advaipbl-modal-cancel', function () {
                modalBlocked.fadeOut('fast');
            });

            processBlockedBtn.on('click', function (e) {
                e.preventDefault();
                const ipList = textareaBlocked.val().trim();
                const duration = durationBlockedSelect.val();

                if (!ipList) {
                    alert('Please enter at least one IP address or CIDR range or upload a CSV.');
                    return;
                }

                processBlockedBtn.prop('disabled', true).text('Processing...');
                resultsBlockedDiv.hide().empty();

                $.post(ajaxurl, {
                    action: 'advaipbl_bulk_import_blocked_ips',
                    nonce: adminData.nonces.bulk_import_blocked_nonce,
                    ip_list: ipList,
                    duration: duration
                }).done(function (response) {
                    if (response.success) {
                        const msgClass = response.data.skipped > 0 ? 'notice-warning' : 'notice-success';
                        const resultsHtml = `<div class="notice ${msgClass} inline"><p>${response.data.message}</p></div>`;
                        resultsBlockedDiv.html(resultsHtml).show();
                        if (response.data.imported > 0) {
                            setTimeout(function () { location.reload(); }, 2000);
                        }
                    } else {
                        resultsBlockedDiv.html(`<div class="notice notice-error inline"><p>${response.data.message}</p></div>`).show();
                    }
                }).fail(function () {
                    resultsBlockedDiv.html('<div class="notice notice-error inline"><p>System error occurred during import.</p></div>').show();
                }).always(function () {
                    processBlockedBtn.prop('disabled', false).text('Import IPs');
                });
            });

            exportBlockedBtn.on('click', function (e) {
                e.preventDefault();
                const originalText = exportBlockedBtn.text();
                exportBlockedBtn.prop('disabled', true).text('Generating...');

                $.post(ajaxurl, {
                    action: 'advaipbl_bulk_export_blocked_ips',
                    nonce: adminData.nonces.bulk_export_blocked_nonce
                }).done(function (response) {
                    if (response.success) {
                        const link = document.createElement('a');
                        link.href = response.data.file_url;
                        link.download = response.data.filename;
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                    } else {
                        alert(response.data.message || 'Export failed.');
                    }
                }).fail(function () {
                    alert('System error occurred during export.');
                }).always(function () {
                    exportBlockedBtn.prop('disabled', false).text(originalText);
                });
            });
        }
    }

    initEndpointLockdownActions();
    initBulkImportExport();

});
