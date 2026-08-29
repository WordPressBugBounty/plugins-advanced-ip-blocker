jQuery(document).ready(function($) {
    var filesToScan = [];
    var totalFiles = 0;
    var scannedFilesCount = 0;
    var chunkSize = 100;
    
    var cleanCount = 0;
    var modifiedCount = 0;
    var unverifiablePlugins = {};
    var currentScanStartTime = 0;
    var currentDeepScanPage = 1;
    var deepScanPerPage = 20;
    
    var unverifiablePlugins = {};
    var currentScanStartTime = 0;
    
    // History state
    var currentScanStartTime = Date.now();

        currentScanHistory = {
        scan_type: (typeof scanType !== 'undefined' ? scanType : 'all'),
        clean: 0,
        modified: [],
        uploads: [],
        high_risk: [],
        deep_scan: [],
        unverifiable: [],
        env: { core: {}, plugins: [] },
        timings: { start: currentScanStartTime, end: 0, duration_sec: 0 }
    };

        $('#advaipbl-start-fim-scan').on('click', function(e) {
        e.preventDefault();
        var scanType = $('#fim-scan-type').val();
        
        var $btn = $(this);
        
        if (scanType === 'deep_scan') {
            if (window.AdvaipblAdmin && typeof window.AdvaipblAdmin.showConfirmModal === 'function') {
                window.AdvaipblAdmin.showConfirmModal({
                    title: 'Deep Scan Warning',
                    message: advaipbl_fim_vars.i18n.deep_scan_confirm,
                    confirmText: 'Start Deep Scan',
                    onConfirm: function() {
                        executeScan(scanType, $btn);
                    }
                });
            } else {
                if (!confirm(advaipbl_fim_vars.i18n.deep_scan_confirm)) {
                    return; // User cancelled
                }
                executeScan(scanType, $btn);
            }
        } else {
            executeScan(scanType, $btn);
        }
    });

    function executeScan(scanType, $btn) {
        $btn.prop('disabled', true).text(advaipbl_fim_vars.i18n.gathering);
        $('#advaipbl-fim-history-btn, #fim-load-history-btn, #advaipbl-fim-quarantine-btn, #advaipbl-fim-whitelist-btn').hide();
        
        $('#fim-progress-area').show();
        $('#fim-results-area').hide();
        $('#fim-modified-list').empty();
        $('#fim-unverifiable-list').empty();
        $('#fim-highrisk-list').empty();
        $('#fim-uploads-list').empty();
        $('#fim-environment-summary').hide();
        $('#fim-results-unverifiable-box').hide();
        $('#fim-progress-bar').css('width', '0%');
        
        filesToScan = [];
        totalFiles = 0;
        scannedFilesCount = 0;
        cleanCount = 0;
        modifiedCount = 0;
        unverifiablePlugins = {};
        currentScanStartTime = Date.now();
        
        currentScanStartTime = Date.now();

        currentScanHistory = {
            scan_type: scanType,
            clean: 0,
            modified: [],
            uploads: [],
            high_risk: [],
            deep_scan: [],
            unverifiable: [],
            env: { core: {}, plugins: [] },
            timings: { start: currentScanStartTime, end: 0, duration_sec: 0 }
        };

        

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'advaipbl_fim_get_files',
                scan_type: scanType,
                nonce: advaipbl_fim_vars.nonce
            },
            success: function(response) {
                if (response.success && response.data.files.length > 0) {
                    if (response.data.warning) {
                        if (window.AdvaipblAdmin && typeof window.AdvaipblAdmin.showConfirmModal === 'function') {
                            window.AdvaipblAdmin.showConfirmModal({ title: advaipbl_fim_vars.i18n.warning || 'Warning', message: response.data.warning, confirmText: 'OK' });
                            // Hide cancel button
                            setTimeout(function() { $('#advaipbl-general-confirm-modal .advaipbl-modal-cancel').hide(); }, 10);
                            setTimeout(function() { $('#advaipbl-general-confirm-modal .advaipbl-modal-cancel').show(); }, 1000);
                        } else {
                            alert(response.data.warning);
                        }
                    }
                    filesToScan = response.data.files;
                    totalFiles = response.data.total;
                    $('#fim-status-text').text(advaipbl_fim_vars.i18n.scanning);
                    processChunk();
                } else {
                    alert(advaipbl_fim_vars.i18n.no_files);
                    $btn.prop('disabled', false).text(advaipbl_fim_vars.i18n.start_btn);
                    $('#advaipbl-fim-history-btn, #fim-load-history-btn, #advaipbl-fim-quarantine-btn, #advaipbl-fim-whitelist-btn').show().prop('disabled', false);
                    $('#fim-progress-area').hide();
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                handleFimError(jqXHR, advaipbl_fim_vars.i18n.error_server);
                $btn.prop('disabled', false).text(advaipbl_fim_vars.i18n.start_btn);
                    $('#advaipbl-fim-history-btn, #fim-load-history-btn, #advaipbl-fim-quarantine-btn, #advaipbl-fim-whitelist-btn').show().prop('disabled', false);
                $('#fim-progress-area').hide();
            }
        });
        }

    function processChunk() {
        if (filesToScan.length === 0) {
            finishScan();
            return;
        }

        var chunk = filesToScan.splice(0, chunkSize);
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'advaipbl_fim_scan_chunk',
                files: chunk,
                nonce: advaipbl_fim_vars.nonce
            },
            success: function(response) {
                if (response.success) {
                    var results = response.data.results;
                    
                    results.forEach(function(res) {
                        scannedFilesCount++;
                        
                        if (res.status === 'clean') {
                            cleanCount++;
                            currentScanHistory.clean++;
                        } else if (res.status === 'unverifiable') {
                            unverifiablePlugins[res.name] = true;
                        } else if (res.status === 'malware_scan') {
                            var html = '<tr>' + '<td><code>' + res.rel_path + '</code></td>' +
                            getMalwareCellHtml(res) +
                                '</tr>';
                            $('#fim-uploads-list').append(html);
                            currentScanHistory.uploads.push(res);
                        } else if (res.status === 'high_risk_scan') {
                            var html = '<tr>' + '<td><code>' + res.rel_path + '</code></td>' +
                            getMalwareCellHtml(res) +
                                '</tr>';
                            $('#fim-highrisk-list').append(html);
                            currentScanHistory.high_risk.push(res);
                        } else if (res.status === 'deep_scan_file') {
                            currentScanHistory.deep_scan.push(res);
                        } else {
                            modifiedCount++;
                            var typeLabel = res.type === 'core' ? 'WordPress Core' : 'Plugin';
                            var reason = res.status === 'missing' ? 'Missing File' : 'Hash Mismatch';
                            
                            var html = '<tr>' + '<td><code>' + res.rel_path + '</code></td>' +
                            '<td>' + typeLabel + '</td>' +
                                '<td style="color: #d63638; font-weight: bold;">' + reason + '</td>' +
                                getMalwareCellHtml(res) +
                                '</tr>';
                            $('#fim-modified-list').append(html);
                            currentScanHistory.modified.push(res);
                        }
                    });
                    
                    renderDeepScanPagination();

                    var pct = Math.round((scannedFilesCount / totalFiles) * 100);
                    if(pct > 100) pct = 100;
                    
                    $('#fim-progress-bar').css('width', pct + '%');
                    $('#fim-progress-stats').text(scannedFilesCount + ' / ' + totalFiles + ' files scanned');

                    // Continue with next chunk
                    processChunk();
                } else {
                    alert(advaipbl_fim_vars.i18n.error_chunk);
                    $('#advaipbl-start-fim-scan').prop('disabled', false).text(advaipbl_fim_vars.i18n.start_btn);
                $('#advaipbl-fim-history-btn, #fim-load-history-btn, #advaipbl-fim-quarantine-btn, #advaipbl-fim-whitelist-btn').show().prop('disabled', false);
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                handleFimError(jqXHR, advaipbl_fim_vars.i18n.error_server_chunk);
                $('#advaipbl-start-fim-scan').prop('disabled', false).text(advaipbl_fim_vars.i18n.start_btn);
                $('#advaipbl-fim-history-btn, #fim-load-history-btn, #advaipbl-fim-quarantine-btn, #advaipbl-fim-whitelist-btn').show().prop('disabled', false);
            }
        });
    }

    function finishScan() {
        $('#fim-status-text').text(advaipbl_fim_vars.i18n.scan_complete);
        $('#advaipbl-start-fim-scan').prop('disabled', false).text(advaipbl_fim_vars.i18n.scan_again);
        $('#advaipbl-fim-history-btn, #fim-load-history-btn, #advaipbl-fim-quarantine-btn, #advaipbl-fim-whitelist-btn').show().prop('disabled', false);
        
        // Populate Unverifiable
        for (var pName in unverifiablePlugins) {
            $('#fim-unverifiable-list').append('<li>' + pName + '</li>');
            currentScanHistory.unverifiable.push(pName);
        }
        
        if (Object.keys(unverifiablePlugins).length > 0) {
            $('#fim-results-unverifiable-box').show();
        } else {
            $('#fim-results-unverifiable-box').hide();
        }

        if (modifiedCount > 0) {
            $('#fim-results-modified-box').show();
        } else {
            $('#fim-results-modified-box').hide();
        }

        var hrCount = $('#fim-highrisk-list tr').length;
        if (hrCount > 0) {
            $('#fim-results-highrisk-box').show();
        } else {
            $('#fim-results-highrisk-box').hide();
        }

        var uploadsCount = $('#fim-uploads-list tr').length;
        if (uploadsCount > 0) {
            $('#fim-results-uploads-box').show();
            $('#fim-uploads-empty-msg').hide();
            $('#fim-uploads-table').show();
        } else {
            $('#fim-results-uploads-box').show();
            $('#fim-uploads-empty-msg').show();
            $('#fim-uploads-table').hide();
        }
        
        var uploadsCount = $('#fim-uploads-list tr').length;
        var sType = currentScanHistory.scan_type || 'all';
        
        if (sType === 'deep_scan') {
            $('#fim-results-uploads-box').hide();
            $('#fim-results-clean-box').hide();
            
            var deepScanCount = $('#fim-deepscan-list tr').length;
            if (deepScanCount > 0) {
                $('#fim-results-deepscan-box').show();
                $('#fim-deepscan-empty-msg').hide();
                $('#fim-deepscan-table').show();
            } else {
                $('#fim-results-deepscan-box').show();
                $('#fim-deepscan-empty-msg').show();
                $('#fim-deepscan-table').hide();
            }
        } else {
            $('#fim-results-deepscan-box').hide();
            $('#fim-results-clean-box').show();
            
            if (uploadsCount > 0) {
                $('#fim-results-uploads-box').show();
                $('#fim-uploads-empty-msg').hide();
                $('#fim-uploads-table').show();
            } else {
                $('#fim-results-uploads-box').show();
                $('#fim-uploads-empty-msg').show();
                $('#fim-uploads-table').hide();
            }
        }

        $('#fim-clean-count').text(cleanCount);
        
        var endTime = Date.now();
        var durationSec = Math.floor((endTime - currentScanStartTime) / 1000);
        currentScanHistory.timings.end = endTime;
        currentScanHistory.timings.duration_sec = durationSec;
        renderTimings(currentScanHistory.timings);
        
        $('#fim-results-area').fadeIn();
        
        // Fetch recommendations and then save history
        fetchUpdateRecommendations(function(envData) {
            currentScanHistory.env = envData;
            
            // Save to history
            $.post(ajaxurl, {
                action: 'advaipbl_fim_save_history',
                nonce: advaipbl_fim_vars.nonce,
                history_data: JSON.stringify(currentScanHistory)
            });
        });
    }

    
    function getMalwareCellHtml(res) {
        if (!res.malware || res.malware === 'Clean') {
            return '<td><span style="color: #00a32a; font-weight: bold;">&#x2705; Clean</span></td><td></td>';
        } else if (res.malware === 'Whitelisted') {
            return '<td><span style="color: #8c8f94; font-weight: bold;">&#x2714; ' + advaipbl_fim_vars.i18n.whitelisted + '</span></td>' +
                   '<td><button type="button" class="button advaipbl-remove-whitelist-btn" data-path="' + res.rel_path + '">' + advaipbl_fim_vars.i18n.remove_whitelist + '</button></td>';
        } else {
            var actionsHtml = '<button type="button" class="button advaipbl-add-whitelist-btn" data-path="' + res.rel_path + '">' + advaipbl_fim_vars.i18n.mark_safe + '</button>';
            
            if (res.type === 'upload_php' || res.type === 'deep_scan_file' || res.type === 'high_risk') {
                if (res.rel_path.indexOf('wp-content/plugins/') !== 0 && res.rel_path.indexOf('wp-admin/') !== 0 && res.rel_path.indexOf('wp-includes/') !== 0 && res.rel_path.indexOf('wp-content/themes/') !== 0) {
                    actionsHtml += ' <button type="button" class="button advaipbl-quarantine-btn" style="color: #d63638; border-color: #d63638; margin-left: 5px;" data-path="' + res.rel_path + '" data-malware="' + res.malware + '">' + advaipbl_fim_vars.i18n.quarantine_btn + '</button>';
                }
            }
            
            return '<td><span style="color: #d63638; font-weight: bold;">&#x1F6A8; ' + res.malware + '</span></td>' +
                   '<td>' + actionsHtml + '</td>';
        }
    }

    function renderTimings(timings) {
        if (!timings || !timings.start) return;
        var startStr = new Date(timings.start).toLocaleString();
        var endStr = timings.end ? new Date(timings.end).toLocaleString() : '--';
        var dSec = timings.duration_sec || 0;
        var mins = Math.floor(dSec / 60);
        var secs = dSec % 60;
        var durStr = mins > 0 ? mins + 'm ' + secs + 's' : secs + 's';
        
        var typeLabels = {
            'all': 'Core + Plugins',
            'core': 'WordPress Core Only',
            'plugins': 'Plugins Only',
            'deep_scan': 'Deep Scan (All PHP Files)'
        };
        var sType = currentScanHistory.scan_type || 'all';
        var typeStr = typeLabels[sType] || sType;
        
        $('#fim-timing-type').text(typeStr);
        $('#fim-timing-start').text(startStr);
        $('#fim-timing-end').text(endStr);
        $('#fim-timing-duration').text(durStr);
    }
    
    function renderEnvironment(data, unvPluginsObj) {
        var $tbody = $('#fim-env-summary-body');
        $tbody.empty();
        
        var getBadge = function(updateAvailable, newVersion, isUnverifiable) {
            if (updateAvailable) {
                var updateUrl = advaipbl_fim_vars.update_url || '';
                var text = advaipbl_fim_vars.i18n.update_avail + ' (' + newVersion + ')';
                var html = '<a href="' + updateUrl + '" target="_blank" style="color: inherit; text-decoration: underline;">' + text + '</a>';
                return '<span style="color: #d63638; font-weight: bold;">🚨 ' + html + '</span>';
            }
            if (isUnverifiable) {
                return '<span style="color: #8c8f94; font-weight: bold;">🛡️ ' + advaipbl_fim_vars.i18n.unverifiable_status + '</span>';
            }
            return '<span style="color: #00a32a; font-weight: bold;">✅ ' + advaipbl_fim_vars.i18n.up_to_date + '</span>';
        };
        
        var coreBadge = getBadge(data.core.update_available, data.core.new_version, false);
        $tbody.append('<tr><td><strong>WordPress Core</strong></td><td>' + data.core.version + '</td><td>' + coreBadge + '</td></tr>');
        
        if (data.plugins && data.plugins.length > 0) {
            data.plugins.forEach(function(p) {
                var isUnv = (unvPluginsObj && unvPluginsObj.hasOwnProperty(p.name));
                var badge = getBadge(p.update_available, p.new_version, isUnv);
                $tbody.append('<tr><td>' + p.name + '</td><td>' + p.version + '</td><td>' + badge + '</td></tr>');
            });
        }
        $('#fim-environment-summary').fadeIn();
    }
    
    function fetchUpdateRecommendations(callback) {
        $.post(ajaxurl, {
            action: 'advaipbl_fim_get_updates',
            nonce: advaipbl_fim_vars.nonce
        }, function(response) {
            if (response.success) {
                var data = response.data;
                renderEnvironment(data, unverifiablePlugins);
                if (callback) callback(data);
            }
        });
    }

    function renderDeepScanPagination() {
        var totalItems = currentScanHistory.deep_scan ? currentScanHistory.deep_scan.length : 0;
        if (totalItems === 0) {
            $('#fim-deepscan-pagination').hide();
            $('#fim-deepscan-list').empty();
            return;
        }
        var totalPages = Math.ceil(totalItems / deepScanPerPage);
        if (currentDeepScanPage < 1) currentDeepScanPage = 1;
        if (currentDeepScanPage > totalPages) currentDeepScanPage = totalPages;
        var startIdx = (currentDeepScanPage - 1) * deepScanPerPage;
        var endIdx = startIdx + deepScanPerPage;
        var pageItems = currentScanHistory.deep_scan.slice(startIdx, endIdx);
        $('#fim-deepscan-list').empty();
        pageItems.forEach(function(res) {
            var html = '<tr><td><code>' + res.rel_path + '</code></td>' + getMalwareCellHtml(res) + '</tr>';
            $('#fim-deepscan-list').append(html);
        });
        $('#fim-deepscan-page-info').text('Page ' + currentDeepScanPage + ' of ' + totalPages);
        $('#fim-deepscan-prev').prop('disabled', currentDeepScanPage === 1);
        $('#fim-deepscan-next').prop('disabled', currentDeepScanPage === totalPages);
        $('#fim-deepscan-pagination').css('display', 'flex');
    }

    function handleFimError(jqXHR, defaultMsg) {
        var status = jqXHR.status;
        var detailedMsg = defaultMsg + ' (HTTP ' + status + ')';
        if (status === 500 || status === 503 || status === 504) {
            detailedMsg += '\nPossible timeout or server resource limit reached. Try reducing chunk size if this persists.';
        } else if (status === 403) {
            detailedMsg += '\nForbidden. A local WAF might be blocking the request due to file paths in the POST body.';
        }
        
        alert(detailedMsg);
        $('#fim-status-text').text('Error: HTTP ' + status);
        
        // Log the error silently
        $.post(ajaxurl, {
            action: 'advaipbl_fim_log_error',
            nonce: advaipbl_fim_vars.nonce,
            error_msg: detailedMsg
        });
    }

    
    
    // --- History UI Logic ---
    
    $('#advaipbl-fim-history-btn').on('click', function(e) {
        e.preventDefault();
        $('#advaipbl-fim-history-modal').show();
        var $list = $('#advaipbl-fim-history-list');
        $list.html('<span class="spinner is-active" style="float:none; margin:0;"></span>');
        
        $.post(ajaxurl, {
            action: 'advaipbl_fim_get_history',
            nonce: advaipbl_fim_vars.nonce
        }, function(response) {
            if (response.success) {
                var history = response.data;
                if (!history || history.length === 0) {
                    $list.html('<p>No history available.</p>');
                    return;
                }
                
                var html = '<table class="widefat striped"><thead><tr><th>Date</th><th>Action</th></tr></thead><tbody>';
                history.forEach(function(h, index) {
                    var d = new Date(h.timestamp * 1000);
                    var dateStr = d.toLocaleString();
                    html += '<tr>';
                    html += '<td>' + dateStr + '</td>';
                    html += '<td><button type="button" class="button advaipbl-load-history-btn" data-index="' + index + '">Load</button></td>';
                    html += '</tr>';
                });
                html += '</tbody></table>';
                $list.html(html);
                
                // Store in global memory for quick loading
                window.advaipblFimHistory = history;
            } else {
                $list.html('<p style="color:red;">Failed to load history.</p>');
            }
        });
    });
    
    $('.advaipbl-modal-cancel').on('click', function(e) {
        e.preventDefault();
        $(this).closest('.advaipbl-modal-overlay').hide();
    });
    
    $(document).on('click', '.advaipbl-load-history-btn', function(e) {
        e.preventDefault();
        var index = $(this).data('index');
        var data = window.advaipblFimHistory[index];
        
        if (data) {
            loadScanFromData(data);
            $('#advaipbl-fim-history-modal').hide();
        }
    });
    
    function loadScanFromData(data) {
        // Reset DOM
        $('#fim-progress-area').hide();
        $('#fim-results-area').show();
        $('#fim-modified-list').empty();
        $('#fim-unverifiable-list').empty();
        $('#fim-highrisk-list').empty();
        $('#fim-uploads-list').empty();
        
        // 0. Timings & State
        currentScanHistory = data;
        if (data.timings) {
            renderTimings(data.timings);
        } else {
            // Backwards compatibility for older scans
            $('#fim-timing-start').text(new Date(data.timestamp * 1000).toLocaleString());
            $('#fim-timing-end').text('--');
            $('#fim-timing-duration').text('--');
        }
        
        // 1. Unverifiable
        var unvObj = {};
        if (data.unverifiable) {
            data.unverifiable.forEach(function(pName) {
                unvObj[pName] = true;
                $('#fim-unverifiable-list').append('<li>' + pName + '</li>');
            });
        }
        if (data.unverifiable && data.unverifiable.length > 0) {
            $('#fim-results-unverifiable-box').show();
        } else {
            $('#fim-results-unverifiable-box').hide();
        }
        
        // 2. Modified
        if (data.modified && data.modified.length > 0) {
            data.modified.forEach(function(res) {
                var typeLabel = res.type === 'core' ? 'WordPress Core' : 'Plugin';
                var reason = res.status === 'missing' ? 'Missing File' : 'Hash Mismatch';
                var html = '<tr>' + '<td><code>' + res.rel_path + '</code></td>' +
                '<td>' + typeLabel + '</td>' +
                                '<td style="color: #d63638; font-weight: bold;">' + reason + '</td>' +
                                getMalwareCellHtml(res) +
                                '</tr>';
                $('#fim-modified-list').append(html);
            });
            $('#fim-results-modified-box').show();
        } else {
            $('#fim-results-modified-box').hide();
        }
        
        // 3a. High Risk
        if (data.high_risk && data.high_risk.length > 0) {
            data.high_risk.forEach(function(res) {
                var html = '<tr>' + '<td><code>' + res.rel_path + '</code></td>' +
                getMalwareCellHtml(res) +
                                '</tr>';
                $('#fim-highrisk-list').append(html);
            });
            $('#fim-results-highrisk-box').show();
        } else {
            $('#fim-results-highrisk-box').hide();
        }
        
        // 3b. Uploads
        if (data.uploads && data.uploads.length > 0) {
            data.uploads.forEach(function(res) {
                var html = '<tr>' + '<td><code>' + res.rel_path + '</code></td>' +
                getMalwareCellHtml(res) +
                                '</tr>';
                $('#fim-uploads-list').append(html);
            });
        }
        
        if (currentScanHistory.deep_scan) {
            currentDeepScanPage = 1;
            renderDeepScanPagination();
        }
        var sType = currentScanHistory.scan_type || 'all';
        var uploadsCount = $('#fim-uploads-list tr').length;
        var deepScanCount = currentScanHistory.deep_scan ? currentScanHistory.deep_scan.length : 0;
        var hrCount = $('#fim-highrisk-list tr').length;
        
        if (sType === 'deep_scan') {
            $('#fim-results-unverifiable-box').hide();
            $('#fim-results-modified-box').hide();
            $('#fim-results-highrisk-box').hide();
            $('#fim-results-uploads-box').hide();
            $('#fim-results-clean-box').hide();
            
            $('#fim-results-deepscan-box').show();
            if (deepScanCount > 0) {
                $('#fim-deepscan-empty-msg').hide();
                $('#fim-deepscan-table').show();
            } else {
                $('#fim-deepscan-empty-msg').show();
                $('#fim-deepscan-table').hide();
            }
        } else {
            $('#fim-results-deepscan-box').hide();
            $('#fim-results-clean-box').show();
            
            // Adjust unverifiable visibility if core
            if (sType === 'core') {
                $('#fim-results-unverifiable-box').hide();
            }
            
            // Uploads visibility
            if (uploadsCount > 0) {
                $('#fim-results-uploads-box').show();
                $('#fim-uploads-empty-msg').hide();
                $('#fim-uploads-table').show();
            } else {
                $('#fim-results-uploads-box').show();
                $('#fim-uploads-empty-msg').show();
                $('#fim-uploads-table').hide();
            }
        }
        
        // 4. Clean Count
        $('#fim-clean-count').text(data.clean || 0);
        
        // 5. Environment
        if (data.env) {
            renderEnvironment(data.env, unvObj);
        }
    }
    

    
    $('#fim-send-email-btn').on('click', function(e) {
        e.preventDefault();
        
        // Helper to show modal
        function showMsg(title, msg) {
            if (window.AdvaipblAdmin && typeof window.AdvaipblAdmin.showConfirmModal === 'function') {
                window.AdvaipblAdmin.showConfirmModal({ title: title, message: msg, confirmText: 'OK' });
                // Hide the cancel button if it exists since it's just an info popup
                setTimeout(function() {
                    $('#advaipbl-general-confirm-modal .advaipbl-modal-cancel').hide();
                }, 10);
            } else {
                alert(msg);
            }
        }
        
        if (!currentScanHistory || (!currentScanHistory.timings && !currentScanHistory.timestamp)) {
            showMsg(advaipbl_fim_vars.i18n.error, 'No scan data available to send.');
            return;
        }
        
        var $btn = $(this);
        var originalHtml = $btn.html();
        $btn.prop('disabled', true).text('Sending...');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'advaipbl_fim_email_report',
                history_data: JSON.stringify(currentScanHistory),
                nonce: advaipbl_fim_vars.nonce
            },
            success: function(response) {
                if (response.success) {
                    showMsg(advaipbl_fim_vars.i18n.success, 'Report sent successfully to your configured email.');
                } else {
                    showMsg(advaipbl_fim_vars.i18n.error, 'Error: ' + (response.data || 'Failed to send'));
                }
            },
            error: function() {
                showMsg(advaipbl_fim_vars.i18n.error, 'Server error occurred while sending email.');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalHtml);
                // Restore cancel button for future confirm modals
                setTimeout(function() {
                    $('#advaipbl-general-confirm-modal .advaipbl-modal-cancel').show();
                }, 1000);
            }
        });
    });
    $('#fim-load-history-btn').on('click', function(e) {
        e.preventDefault();
        var $btn = $(this);
        var originalHtml = $btn.html();
        $btn.prop('disabled', true).text('Loading...');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'advaipbl_fim_get_history',
                nonce: advaipbl_fim_vars.nonce
            },
            success: function(response) {
                if (response.success && response.data) {
                    var history = response.data;
                    if (!history || history.length === 0) {
                        $('#fim-history-list').html('<p>No history available.</p>');
                        return;
                    }
                    var html = '<table class="widefat striped"><thead><tr><th>Date</th><th>Action</th></tr></thead><tbody>';
                    history.forEach(function(h, index) {
                        var d = new Date(h.timestamp * 1000);
                        html += '<tr><td>' + d.toLocaleString() + '</td>';
                        html += '<td><button type="button" class="button advaipbl-load-history-item-btn" data-index="' + index + '">Load</button></td></tr>';
                    });
                    html += '</tbody></table>';
                    $('#fim-history-list').html(html);
                    $('#fim-history-modal').fadeIn();
                } else {
                    alert('No history found.');
                }
            },
            error: function() {
                alert('Server error.');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });

    $('#fim-history-modal-close').on('click', function() {
        $('#fim-history-modal').fadeOut();
    });

    $(document).on('click', '.advaipbl-load-history-item-btn', function() {
        var idx = $(this).data('index');
        $.post(ajaxurl, {
            action: 'advaipbl_fim_get_history',
            nonce: advaipbl_fim_vars.nonce
        }, function(response) {
            if (response.success && response.data && response.data[idx]) {
                var historyData = response.data[idx].data;
                $('#fim-history-modal').fadeOut();
                loadScanFromData(historyData);
            }
        });
    });

    $(document).on('click', '.advaipbl-add-whitelist-btn', function() {
        var btn = $(this);
        var path = btn.data('path');
        if (window.AdvaipblAdmin && typeof window.AdvaipblAdmin.showConfirmModal === 'function') {
            window.AdvaipblAdmin.showConfirmModal({
                title: advaipbl_fim_vars.i18n.mark_safe,
                message: advaipbl_fim_vars.i18n.confirm_mark_safe,
                confirmText: advaipbl_fim_vars.i18n.mark_safe,
                onConfirm: function() {
                    $.post(ajaxurl, {
                        action: 'advaipbl_fim_add_whitelist',
                        nonce: advaipbl_fim_vars.nonce,
                        rel_path: path
                    }, function(response) {
                        if (response.success) {
                            var tr = btn.closest('tr');
                            tr.find('td:nth-last-child(2)').html('<span style="color: #8c8f94; font-weight: bold;">&#x2714; ' + advaipbl_fim_vars.i18n.whitelisted + '</span>');
                            btn.replaceWith('<button type="button" class="button advaipbl-remove-whitelist-btn" data-path="' + path + '">' + advaipbl_fim_vars.i18n.remove_whitelist + '</button>');
                        }
                    });
                }
            });
        }
    });

    $(document).on('click', '.advaipbl-remove-whitelist-btn', function() {
        var btn = $(this);
        var path = btn.data('path');
        if (window.AdvaipblAdmin && typeof window.AdvaipblAdmin.showConfirmModal === 'function') {
            window.AdvaipblAdmin.showConfirmModal({
                title: advaipbl_fim_vars.i18n.remove_whitelist,
                message: advaipbl_fim_vars.i18n.confirm_remove_whitelist,
                confirmText: advaipbl_fim_vars.i18n.remove_whitelist,
                onConfirm: function() {
                    $.post(ajaxurl, {
                        action: 'advaipbl_fim_remove_whitelist',
                        nonce: advaipbl_fim_vars.nonce,
                        rel_path: path
                    }, function(response) {
                        if (response.success) {
                            var tr = btn.closest('tr');
                            tr.find('td:nth-last-child(2)').html('<span style="color: #d63638; font-weight: bold;">&#x1F6A8; Removed from Whitelist</span>');
                            btn.replaceWith('<button type="button" class="button advaipbl-add-whitelist-btn" data-path="' + path + '">' + advaipbl_fim_vars.i18n.mark_safe + '</button>');
                        }
                    });
                }
            });
        }
    });

    $('#fim-deepscan-prev').on('click', function() {
        if (currentDeepScanPage > 1) {
            currentDeepScanPage--;
            renderDeepScanPagination();
        }
    });

    $('#fim-deepscan-next').on('click', function() {
        currentDeepScanPage++;
        renderDeepScanPagination();
    });





    // --- QUARANTINE SYSTEM ---
    
    // Open Vault Modal
    // FIM Whitelist Modal
    $('#advaipbl-fim-whitelist-btn').on('click', function(e) {
        e.preventDefault();
        $('#advaipbl-fim-whitelist-modal').show();
        loadFIMWhitelist();
    });

    function loadFIMWhitelist() {
        $('#advaipbl-fim-whitelist-loading').show();
        $('#advaipbl-fim-whitelist-empty').hide();
        $('#advaipbl-fim-whitelist-list-container').hide();
        
        $.post(ajaxurl, {
            action: 'advaipbl_fim_get_whitelist_list',
            nonce: advaipbl_fim_vars.nonce
        }, function(response) {
            $('#advaipbl-fim-whitelist-loading').hide();
            if (response.success && response.data.length > 0) {
                var $tbody = $('#advaipbl-fim-whitelist-tbody');
                $tbody.empty();
                response.data.forEach(function(path) {
                    var html = '<tr>' +
                        '<td><code>' + path + '</code></td>' +
                        '<td style="text-align:center;">' +
                            '<button type="button" class="button button-link-delete advaipbl-remove-whitelist-modal-btn" data-path="' + path + '"><span class="dashicons dashicons-trash"></span> ' + (advaipbl_fim_vars.i18n.ignore_btn ? advaipbl_fim_vars.i18n.ignore_btn.replace('Ignore', 'Remove') : 'Remove') + '</button>' +
                        '</td>' +
                    '</tr>';
                    $tbody.append(html);
                });
                $('#advaipbl-fim-whitelist-list-container').show();
            } else {
                $('#advaipbl-fim-whitelist-empty').show();
            }
        });
    }

    $(document).on('click', '.advaipbl-remove-whitelist-modal-btn', function(e) {
        e.preventDefault();
        var $btn = $(this);
        var path = $btn.data('path');
        $btn.prop('disabled', true).text('...');
        
        $.post(ajaxurl, {
            action: 'advaipbl_fim_remove_whitelist',
            nonce: advaipbl_fim_vars.nonce,
            rel_path: path
        }, function(response) {
            if (response.success) {
                loadFIMWhitelist();
            } else {
                alert(response.data.message || advaipbl_fim_vars.i18n.error);
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-trash"></span> Remove');
            }
        });
    });

    $('#advaipbl-fim-quarantine-btn').on('click', function(e) {
        e.preventDefault();
        $('#advaipbl-fim-quarantine-modal').show();
        loadQuarantineVault();
    });
    
    function loadQuarantineVault() {
        $('#advaipbl-fim-quarantine-loading').show();
        $('#advaipbl-fim-quarantine-empty').hide();
        $('#advaipbl-fim-quarantine-list-container').hide();
        
        $.post(ajaxurl, {
            action: 'advaipbl_fim_get_quarantine_list',
            nonce: advaipbl_fim_vars.nonce
        }, function(response) {
            $('#advaipbl-fim-quarantine-loading').hide();
            if (response.success && response.data.length > 0) {
                var $tbody = $('#advaipbl-fim-quarantine-tbody');
                $tbody.empty();
                response.data.forEach(function(item) {
                    var html = '<tr>' +
                        '<td><code>' + item.original_path + '</code></td>' +
                        '<td>' + item.malware_type + '</td>' +
                        '<td>' + item.timestamp + '</td>' +
                        '<td>' +
                            '<button type="button" class="button advaipbl-restore-quarantine-btn" data-id="' + item.id + '" style="margin-right:5px;">' + advaipbl_fim_vars.i18n.restore_btn + '</button>' +
                            '<button type="button" class="button advaipbl-delete-quarantine-btn" data-id="' + item.id + '" style="color: #d63638; border-color: #d63638;">' + advaipbl_fim_vars.i18n.delete_btn + '</button>' +
                        '</td>' +
                    '</tr>';
                    $tbody.append(html);
                });
                $('#advaipbl-fim-quarantine-list-container').show();
            } else {
                $('#advaipbl-fim-quarantine-empty').show();
            }
        });
    }

    // Handle Quarantine Action
    $(document).on('click', '.advaipbl-quarantine-btn', function(e) {
        e.preventDefault();
        var $btn = $(this);
        var path = $btn.data('path');
        var malware = $btn.data('malware');

        if (window.AdvaipblAdmin && typeof window.AdvaipblAdmin.showConfirmModal === 'function') {
            window.AdvaipblAdmin.showConfirmModal({
                title: advaipbl_fim_vars.i18n.quarantine_title,
                message: advaipbl_fim_vars.i18n.quarantine_msg,
                confirmText: advaipbl_fim_vars.i18n.quarantine_confirm,
                onConfirm: function() {
                    processQuarantine(path, malware, $btn);
                }
            });
        }
    });

    function processQuarantine(path, malware, $btn) {
        $btn.prop('disabled', true).text(advaipbl_fim_vars.i18n.quarantine_moving);
        $.post(ajaxurl, {
            action: 'advaipbl_fim_quarantine_file',
            file_path: path,
            malware_type: malware,
            nonce: advaipbl_fim_vars.nonce
        }, function(response) {
            if (response.success) {
                if (window.AdvaipblAdmin) {
                    window.AdvaipblAdmin.showConfirmModal({ title: advaipbl_fim_vars.i18n.success, message: response.data, confirmText: 'OK' });
                    setTimeout(function() { $('#advaipbl-general-confirm-modal .advaipbl-modal-cancel').hide(); }, 10);
                    setTimeout(function() { $('#advaipbl-general-confirm-modal .advaipbl-modal-cancel').show(); }, 1000);
                }
                var $tr = $btn.closest('tr');
                $tr.find('td').eq(1).html('<span style="color: #f0b849; font-weight: bold;">&#x1F6E1; ' + advaipbl_fim_vars.i18n.quarantined_status + '</span>');
                $tr.find('td').eq(2).html('<button type="button" class="button button-secondary" onclick="jQuery(\'#advaipbl-fim-quarantine-btn\').click();">' + advaipbl_fim_vars.i18n.manage_vault + '</button>');
            } else {
                if (window.AdvaipblAdmin) {
                    window.AdvaipblAdmin.showConfirmModal({ title: advaipbl_fim_vars.i18n.error, message: response.data, confirmText: 'OK' });
                    setTimeout(function() { $('#advaipbl-general-confirm-modal .advaipbl-modal-cancel').hide(); }, 10);
                    setTimeout(function() { $('#advaipbl-general-confirm-modal .advaipbl-modal-cancel').show(); }, 1000);
                }
                $btn.prop('disabled', false).text(advaipbl_fim_vars.i18n.quarantine_btn);
            }
        });
    }

    // Handle Restore Action
    $(document).on('click', '.advaipbl-restore-quarantine-btn', function(e) {
        e.preventDefault();
        var $btn = $(this);
        var id = $btn.data('id');

        if (window.AdvaipblAdmin) {
            window.AdvaipblAdmin.showConfirmModal({
                title: advaipbl_fim_vars.i18n.restore_title,
                message: advaipbl_fim_vars.i18n.restore_msg,
                confirmText: advaipbl_fim_vars.i18n.restore_confirm,
                onConfirm: function() {
                    $btn.prop('disabled', true).text(advaipbl_fim_vars.i18n.restore_restoring);
                    $.post(ajaxurl, {
                        action: 'advaipbl_fim_restore_quarantine',
                        id: id,
                        nonce: advaipbl_fim_vars.nonce
                    }, function(response) {
                        if (response.success) {
                            $btn.closest('tr').fadeOut(400, function() { $(this).remove(); loadQuarantineVault(); });
                        } else {
                            window.AdvaipblAdmin.showConfirmModal({ title: advaipbl_fim_vars.i18n.error, message: response.data, confirmText: 'OK' });
                            $btn.prop('disabled', false).text('Restore');
                        }
                    });
                }
            });
        }
    });

    // Handle Delete Permanently Action
    $(document).on('click', '.advaipbl-delete-quarantine-btn', function(e) {
        e.preventDefault();
        var $btn = $(this);
        var id = $btn.data('id');

        if (window.AdvaipblAdmin) {
            window.AdvaipblAdmin.showConfirmModal({
                title: advaipbl_fim_vars.i18n.delete_title,
                message: advaipbl_fim_vars.i18n.delete_msg,
                confirmText: advaipbl_fim_vars.i18n.delete_confirm,
                onConfirm: function() {
                    $btn.prop('disabled', true).text(advaipbl_fim_vars.i18n.delete_deleting);
                    $.post(ajaxurl, {
                        action: 'advaipbl_fim_delete_quarantine',
                        id: id,
                        nonce: advaipbl_fim_vars.nonce
                    }, function(response) {
                        if (response.success) {
                            $btn.closest('tr').fadeOut(400, function() { $(this).remove(); loadQuarantineVault(); });
                        } else {
                            window.AdvaipblAdmin.showConfirmModal({ title: advaipbl_fim_vars.i18n.error, message: response.data, confirmText: 'OK' });
                            $btn.prop('disabled', false).text('Delete');
                        }
                    });
                }
            });
        }
    });

});