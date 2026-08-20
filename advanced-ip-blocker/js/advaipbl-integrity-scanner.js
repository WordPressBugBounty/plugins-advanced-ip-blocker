jQuery(document).ready(function($) {
    var filesToScan = [];
    var totalFiles = 0;
    var scannedFilesCount = 0;
    var chunkSize = 100;
    
    var cleanCount = 0;
    var modifiedCount = 0;
    
    var unverifiablePlugins = {};
    var currentScanStartTime = 0;
    
    // History state
    var currentScanHistory = {
        clean: 0,
        modified: [],
        uploads: [],
        high_risk: [],
        unverifiable: [],
        env: { core: {}, plugins: [] }
    };

    $('#advaipbl-start-fim-scan').on('click', function(e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true).text(advaipbl_fim_vars.i18n.gathering);
        
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
        
        currentScanHistory = {
            clean: 0,
            modified: [],
            uploads: [],
            high_risk: [],
            unverifiable: [],
            env: { core: {}, plugins: [] },
            timings: { start: currentScanStartTime, end: 0, duration_sec: 0 }
        };

        var scanType = $('#fim-scan-type').val();

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
                    filesToScan = response.data.files;
                    totalFiles = response.data.total;
                    $('#fim-status-text').text(advaipbl_fim_vars.i18n.scanning);
                    processChunk();
                } else {
                    alert(advaipbl_fim_vars.i18n.no_files);
                    $btn.prop('disabled', false).text(advaipbl_fim_vars.i18n.start_btn);
                    $('#fim-progress-area').hide();
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                handleFimError(jqXHR, advaipbl_fim_vars.i18n.error_server);
                $btn.prop('disabled', false).text(advaipbl_fim_vars.i18n.start_btn);
                $('#fim-progress-area').hide();
            }
        });
    });

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
                            var mLabel = (!res.malware || res.malware === 'Clean') 
                                ? '<span style="color: #00a32a; font-weight: bold;">✅ Clean</span>' 
                                : '<span style="color: #d63638; font-weight: bold;">🚨 ' + res.malware + '</span>';
                            
                            var html = '<tr>' +
                                '<td><code>' + res.rel_path + '</code></td>' +
                                '<td>' + mLabel + '</td>' +
                                '</tr>';
                            $('#fim-uploads-list').append(html);
                            currentScanHistory.uploads.push(res);
                        } else if (res.status === 'high_risk_scan') {
                            var mLabel = (!res.malware || res.malware === 'Clean') 
                                ? '<span style="color: #00a32a; font-weight: bold;">✅ Clean</span>' 
                                : '<span style="color: #d63638; font-weight: bold;">🚨 ' + res.malware + '</span>';
                            
                            var html = '<tr>' +
                                '<td><code>' + res.rel_path + '</code></td>' +
                                '<td>' + mLabel + '</td>' +
                                '</tr>';
                            $('#fim-highrisk-list').append(html);
                            currentScanHistory.high_risk.push(res);
                        } else {
                            modifiedCount++;
                            var typeLabel = res.type === 'core' ? 'WordPress Core' : 'Plugin';
                            var reason = res.status === 'missing' ? 'Missing File' : 'Hash Mismatch';
                            
                            var mLabel = '';
                            if (res.malware) {
                                mLabel = (res.malware === 'Clean') 
                                    ? '<span style="color: #00a32a; font-weight: bold;">✅ Clean</span>' 
                                    : '<span style="color: #d63638; font-weight: bold;">🚨 ' + res.malware + '</span>';
                            }
                            
                            var html = '<tr>' +
                                '<td><code>' + res.rel_path + '</code></td>' +
                                '<td>' + typeLabel + '</td>' +
                                '<td style="color: #d63638; font-weight: bold;">' + reason + '</td>' +
                                '<td>' + mLabel + '</td>' +
                                '</tr>';
                            $('#fim-modified-list').append(html);
                            currentScanHistory.modified.push(res);
                        }
                    });

                    var pct = Math.round((scannedFilesCount / totalFiles) * 100);
                    if(pct > 100) pct = 100;
                    
                    $('#fim-progress-bar').css('width', pct + '%');
                    $('#fim-progress-stats').text(scannedFilesCount + ' / ' + totalFiles + ' files scanned');

                    // Continue with next chunk
                    processChunk();
                } else {
                    alert(advaipbl_fim_vars.i18n.error_chunk);
                    $('#advaipbl-start-fim-scan').prop('disabled', false).text(advaipbl_fim_vars.i18n.start_btn);
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                handleFimError(jqXHR, advaipbl_fim_vars.i18n.error_server_chunk);
                $('#advaipbl-start-fim-scan').prop('disabled', false).text(advaipbl_fim_vars.i18n.start_btn);
            }
        });
    }

    function finishScan() {
        $('#fim-status-text').text(advaipbl_fim_vars.i18n.scan_complete);
        $('#advaipbl-start-fim-scan').prop('disabled', false).text(advaipbl_fim_vars.i18n.scan_again);
        
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
    
    function renderEnvironment(data, unvPluginsObj) {
        var $tbody = $('#fim-env-summary-body');
        $tbody.empty();
        
        var getBadge = function(updateAvailable, newVersion, isUnverifiable) {
            if (updateAvailable) {
                var updateUrl = advaipbl_fim_vars.update_url || '';
                var text = advaipbl_fim_vars.i18n.update_avail + ' (' + newVersion + ')';
                var html = '<a href="' + updateUrl + '" target="_blank" style="color: inherit; text-decoration: underline;">' + text + '</a>';
                return '<span style="color: #d63638; font-weight: bold;">⚠️ ' + html + '</span>';
            }
            if (isUnverifiable) {
                return '<span style="color: #8c8f94;">🛡️ ' + advaipbl_fim_vars.i18n.unverifiable_status + '</span>';
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
                var mLabel = '';
                if (res.malware) {
                    mLabel = (res.malware === 'Clean') 
                        ? '<span style="color: #00a32a; font-weight: bold;">✅ Clean</span>' 
                        : '<span style="color: #d63638; font-weight: bold;">🚨 ' + res.malware + '</span>';
                }
                var html = '<tr>' +
                    '<td><code>' + res.rel_path + '</code></td>' +
                    '<td>' + typeLabel + '</td>' +
                    '<td style="color: #d63638; font-weight: bold;">' + reason + '</td>' +
                    '<td>' + mLabel + '</td>' +
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
                var mLabel = (!res.malware || res.malware === 'Clean') 
                    ? '<span style="color: #00a32a; font-weight: bold;">✅ Clean</span>' 
                    : '<span style="color: #d63638; font-weight: bold;">🚨 ' + res.malware + '</span>';
                var html = '<tr>' +
                    '<td><code>' + res.rel_path + '</code></td>' +
                    '<td>' + mLabel + '</td>' +
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
                var mLabel = (!res.malware || res.malware === 'Clean') 
                    ? '<span style="color: #00a32a; font-weight: bold;">✅ Clean</span>' 
                    : '<span style="color: #d63638; font-weight: bold;">🚨 ' + res.malware + '</span>';
                var html = '<tr>' +
                    '<td><code>' + res.rel_path + '</code></td>' +
                    '<td>' + mLabel + '</td>' +
                    '</tr>';
                $('#fim-uploads-list').append(html);
            });
            $('#fim-results-uploads-box').show();
            $('#fim-uploads-empty-msg').hide();
            $('#fim-uploads-table').show();
        } else {
            $('#fim-results-uploads-box').show();
            $('#fim-uploads-empty-msg').show();
            $('#fim-uploads-table').hide();
        }
        
        // 4. Clean Count
        $('#fim-clean-count').text(data.clean || 0);
        
        // 5. Environment
        if (data.env) {
            renderEnvironment(data.env, unvObj);
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
        
        $('#fim-timing-start').text(startStr);
        $('#fim-timing-end').text(endStr);
        $('#fim-timing-duration').text(durStr);
    }
    
    $('#fim-send-email-btn').on('click', function(e) {
        e.preventDefault();
        if (!currentScanHistory || (!currentScanHistory.timings && !currentScanHistory.timestamp)) {
            alert('No scan data available to send.');
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
                    alert('Report sent successfully to your configured email.');
                } else {
                    alert('Error: ' + (response.data || 'Failed to send'));
                }
            },
            error: function() {
                alert('Server error occurred while sending email.');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });});
