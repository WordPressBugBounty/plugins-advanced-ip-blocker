<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_File_Verifier
{
    private $main_instance;
    public const OPTION_BASELINE_HASHES = 'advaipbl_fim_baseline_hashes';
    public const OPTION_BASELINE_VERSION = 'advaipbl_fim_baseline_version';

    public function __construct($main_instance)
    {
        $this->main_instance = $main_instance;
    }

    /**
     * Calculates the hash of a critical file.
     *
     * @param string $filepath Absolute path to the file.
     * @return string|false SHA-256 hash or false if file not found.
     */
    public function get_file_hash($filepath)
    {
        if (!file_exists($filepath)) {
            return false;
        }

        if (filesize($filepath) > 2 * 1024 * 1024) {
            return 'skipped_too_large';
        }

        return hash_file('sha256', $filepath);
    }

    /**
     * Gets the list of critical files to monitor.
     * @return array
     */
    public function get_monitored_files()
    {
        $wp_config_path = ABSPATH . 'wp-config.php';
        if (!file_exists($wp_config_path) && file_exists(dirname(ABSPATH) . '/wp-config.php') && !file_exists(dirname(ABSPATH) . '/wp-settings.php')) {
            $wp_config_path = dirname(ABSPATH) . '/wp-config.php';
        }

        return [
            'wp-config.php'   => wp_normalize_path($wp_config_path),
            'index.php'       => wp_normalize_path(ABSPATH . 'index.php'),
            'wp-settings.php' => wp_normalize_path(ABSPATH . 'wp-settings.php'),
            '.htaccess'       => wp_normalize_path(ABSPATH . '.htaccess'),
        ];
    }

    /**
     * Formats bytes into a human-readable string.
     *
     * @param int|null $bytes File size in bytes.
     * @return string Formatted size.
     */
    public function format_file_size($bytes)
    {
        if ($bytes === null || $bytes === false) {
            return 'N/A';
        }

        $bytes = (int) $bytes;
        if (function_exists('size_format')) {
            $formatted = size_format($bytes, 2);
            if ($formatted) {
                return $formatted;
            }
        }

        return $bytes . ' B';
    }

    /**
     * Creates and stores the initial baseline hashes.
     */
    public function create_baseline()
    {
        $baseline = [];
        foreach ($this->get_monitored_files() as $key => $path) {
            $hash = $this->get_file_hash($path);
            if ($hash && $hash !== 'skipped_too_large') {
                $baseline[$key] = [
                    'hash'      => $hash,
                    'size'      => file_exists($path) ? filesize($path) : 0,
                    'timestamp' => time(),
                ];
            }
        }
        update_option(self::OPTION_BASELINE_HASHES, $baseline);
        if (defined('ADVAIPBL_VERSION')) {
            update_option(self::OPTION_BASELINE_VERSION, ADVAIPBL_VERSION);
        }

        return $baseline;
    }

    public function reset_baseline()
    {
        return $this->create_baseline();
    }

    /**
     * Scans files against the stored baseline.
     * @return array List of changed files.
     */
    public function scan_files()
    {
        if (empty($this->main_instance->options['enable_fim'])) {
            return [];
        }

        $baseline = get_option(self::OPTION_BASELINE_HASHES, []);
        $baseline_version = get_option(self::OPTION_BASELINE_VERSION, '');

        if (empty($baseline) || (defined('ADVAIPBL_VERSION') && $baseline_version !== ADVAIPBL_VERSION)) {
            $this->create_baseline();
            if (isset($this->main_instance->audit_logger)) {
                $this->main_instance->audit_logger->log_activity(
                    'fim_info',
                    'info',
                    ['message' => sprintf('FIM baseline automatically synchronized for version %s', defined('ADVAIPBL_VERSION') ? ADVAIPBL_VERSION : '')]
                );
            }

            return [];
        }

        $fim_engine = null;
        $core_checksums = [];
        if (isset($this->main_instance->fim_engine)) {
            $fim_engine = $this->main_instance->fim_engine;
            $core_checksums = $fim_engine->get_core_checksums();
            if (is_wp_error($core_checksums)) {
                $core_checksums = [];
            }
        }

        $changes = [];
        $silent_updates = [];

        foreach ($this->get_monitored_files() as $key => $path) {
            $current_hash = $this->get_file_hash($path);
            $current_size = ($current_hash && file_exists($path)) ? filesize($path) : 0;
            $old_hash = $baseline[$key]['hash'] ?? null;
            $old_size = isset($baseline[$key]['size']) ? (int) $baseline[$key]['size'] : null;

            if (!$current_hash && isset($baseline[$key])) {
                $changes[] = [
                    'file'     => $key,
                    'type'     => 'deleted',
                    'old_hash' => $old_hash,
                    'old_size' => $old_size,
                ];
                continue;
            }

            if ($current_hash && isset($baseline[$key])) {
                if ($current_hash !== $baseline[$key]['hash']) {
                    
                    if (isset($core_checksums[$key]) && md5_file($path) === $core_checksums[$key]) {
                        $silent_updates[] = [
                            'file'     => $key,
                            'type'     => 'official_update',
                            'new_hash' => $current_hash,
                            'new_size' => $current_size,
                        ];
                        continue;
                    }

                    $malware_status = $fim_engine ? $fim_engine->scan_for_malware($path) : 'Unknown';

                    $changes[] = [
                        'file'           => $key,
                        'type'           => 'modified',
                        'old_hash'       => $old_hash,
                        'new_hash'       => $current_hash,
                        'old_size'       => $old_size,
                        'new_size'       => $current_size,
                        'malware_status' => $malware_status,
                    ];
                }
            } elseif ($current_hash && !isset($baseline[$key])) {
                $changes[] = [
                    'file'     => $key,
                    'type'     => 'added',
                    'new_hash' => $current_hash,
                    'new_size' => $current_size,
                ];
            }
        }

        if (!empty($this->main_instance->options['fim_scan_uploads'])) {
            $upload_anomalies = $this->scan_uploads_for_executables();
            $changes = array_merge($changes, $upload_anomalies);
        }

        if (!empty($silent_updates)) {
            foreach ($silent_updates as $upd) {
                $baseline[$upd['file']] = [
                    'hash'      => $upd['new_hash'],
                    'size'      => $upd['new_size'] ?? 0,
                    'timestamp' => time(),
                ];
                if (isset($this->main_instance->audit_logger)) {
                    $this->main_instance->audit_logger->log_activity(
                        'fim_info',
                        'info',
                        ['message' => "WordPress official update applied to {$upd['file']}"]
                    );
                }
            }
            update_option(self::OPTION_BASELINE_HASHES, $baseline);
        }

        if (!empty($changes)) {
            $this->handle_fim_alert($changes);

            $baseline_updated = false;
            foreach ($changes as $change) {
                $file_key = $change['file'] ?? '';
                $type = $change['type'] ?? '';
                if ($type === 'modified' || $type === 'added') {
                    if (!empty($change['new_hash'])) {
                        $baseline[$file_key] = [
                            'hash'      => $change['new_hash'],
                            'size'      => $change['new_size'] ?? 0,
                            'timestamp' => time(),
                        ];
                        $baseline_updated = true;
                    }
                } elseif (isset($baseline[$file_key]) && $type === 'deleted') {
                    unset($baseline[$file_key]);
                    $baseline_updated = true;
                }
            }

            if ($baseline_updated) {
                update_option(self::OPTION_BASELINE_HASHES, $baseline);
            }
        }

        return $changes;
    }

    /**
     * Scans the wp-content/uploads directory for suspicious executable files.
     * @return array List of suspicious files found.
     */
    private function scan_uploads_for_executables()
    {
        $anomalies = [];
        $upload_dir = wp_upload_dir();

        if (empty($upload_dir['basedir']) || !is_dir($upload_dir['basedir'])) {
            return $anomalies;
        }

        $base_dir = $upload_dir['basedir'];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($base_dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        $iterator->setMaxDepth(5);

        $raw_excluded_paths = $this->main_instance->options['fim_excluded_paths'] ?? '';
        $excluded_paths = array_filter(array_map('trim', explode("\n", $raw_excluded_paths)));

        $blacklisted_extensions = ['php', 'php5', 'phtml', 'pl', 'cgi', 'sh'];

        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isFile()) {
                $ext = strtolower($fileinfo->getExtension());
                if (in_array($ext, $blacklisted_extensions, true)) {
                    $filename = $fileinfo->getFilename();
                    $rel_path = str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($fileinfo->getPathname()));

                    if (strpos($rel_path, 'wp-content/uploads/advaipbl_quarantine') !== false) {
                        continue;
                    }

                    $is_excluded = false;
                    foreach ($excluded_paths as $ex) {
                        if (!empty($ex) && strpos($rel_path, $ex) !== false) {
                            $is_excluded = true;
                            break;
                        }
                    }
                    if ($is_excluded) {
                        continue;
                    }

                    if ($filename === 'index.php' && $fileinfo->getSize() < 200) {
                        $content = @file_get_contents($fileinfo->getPathname(), false, null, 0, 100);
                        if ($content !== false && (stripos($content, 'Silence is golden') !== false || trim($content) === '<?php')) {
                            continue;
                        }
                    }

                    $malware_status = 'Unknown';
                    if (isset($this->main_instance->fim_engine)) {
                        $malware_status = $this->main_instance->fim_engine->scan_for_malware($fileinfo->getPathname());
                    }

                    if ($malware_status === 'Clean') {
                        continue;
                    }

                    $anomalies[] = [
                        'file'           => str_replace(ABSPATH, '', $fileinfo->getPathname()),
                        'type'           => 'suspicious_upload',
                        'new_size'       => $fileinfo->getSize(),
                        'malware_status' => $malware_status,
                    ];
                }
            }
        }

        return $anomalies;
    }

    private function handle_fim_alert($changes)
    {
        $change_summary = [];
        foreach ($changes as $change) {
            $diag_parts = [];
            if (!empty($change['old_hash']) && !empty($change['new_hash'])) {
                $diag_parts[] = 'Hash: ' . substr($change['old_hash'], 0, 8) . '... -> ' . substr($change['new_hash'], 0, 8) . '...';
            } elseif (!empty($change['new_hash'])) {
                $diag_parts[] = 'Hash: ' . substr($change['new_hash'], 0, 8) . '...';
            }

            if (isset($change['new_size'])) {
                if (isset($change['old_size']) && $change['old_size'] !== null) {
                    $size_text = 'Size: ' . $this->format_file_size($change['old_size']) . ' -> ' . $this->format_file_size($change['new_size']);
                    if ((int) $change['old_size'] === (int) $change['new_size']) {
                        $size_text .= ' (identical size)';
                    }
                    $diag_parts[] = $size_text;
                } else {
                    $diag_parts[] = 'Size: ' . $this->format_file_size($change['new_size']);
                }
            } elseif (isset($change['old_size']) && $change['old_size'] !== null) {
                $diag_parts[] = 'Former size: ' . $this->format_file_size($change['old_size']);
            }

            $diag_str = !empty($diag_parts) ? ' [' . implode(' | ', $diag_parts) . ']' : '';
            $malware_info = (isset($change['malware_status']) && $change['malware_status'] !== 'Clean' && $change['malware_status'] !== 'Unknown') ? " [{$change['malware_status']}]" : '';
            $change_summary[] = "{$change['file']} ({$change['type']}){$diag_str}{$malware_info}";
        }
        $summary_string = implode(', ', $change_summary);

        if (isset($this->main_instance->audit_logger)) {
            $this->main_instance->audit_logger->log_activity(
                'fim_alert',
                'critical',
                ['message' => 'File integrity changes detected', 'files' => $change_summary]
            );
        } else {
            $this->main_instance->log_event('File Integrity Monitor detected changes: ' . wp_json_encode($changes), 'critical');
        }

        $to = !empty($this->main_instance->options['fim_alert_email'])
            ? $this->main_instance->options['fim_alert_email']
            : get_option('admin_email');

        $site_name = get_bloginfo('name');

        /* translators: %s is a placeholder */
        $subject = sprintf(__('[%s] CRITICAL: File Change Detected', 'advanced-ip-blocker'), $site_name);

        $template_title = __('File Integrity Alert', 'advanced-ip-blocker');

        $date_time = date_i18n(get_option('date_format') . ' ' . get_option('time_format'));
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : 'Unknown';

        $trigger_source = 'Scheduled Cron';
        $user_info = '';

        if (is_admin() && current_user_can('advaipbl_manage_settings') && wp_doing_ajax()) {
            $current_user = wp_get_current_user();
            $trigger_source = 'Manual Scan';
            $user_info = sprintf(' (%s)', $current_user->user_login);
        }

        $body_content = '<p><strong>' . esc_html__('Detection Time:', 'advanced-ip-blocker') . '</strong> ' . esc_html($date_time) . '<br>';
        $body_content .= '<strong>' . esc_html__('Server IP:', 'advanced-ip-blocker') . '</strong> ' . esc_html($server_ip) . '<br>';
        $body_content .= '<strong>' . esc_html__('Trigger:', 'advanced-ip-blocker') . '</strong> ' . esc_html($trigger_source . $user_info) . '</p>';

        $body_content .= '<hr style="border: 0; border-top: 1px solid #eee; margin: 15px 0;">';

        $body_content .= '<p>' . esc_html__('The Advanced IP Blocker File Integrity Monitor has detected unauthorized changes to critical system files:', 'advanced-ip-blocker') . '</p>';
        $body_content .= '<ul style="list-style-type: none; padding-left: 0;">';

        foreach ($changes as $change) {
            $malware_info = (isset($change['malware_status']) && $change['malware_status'] !== 'Clean' && $change['malware_status'] !== 'Unknown') ? ' <strong style="color:#dc3232;">[' . esc_html($change['malware_status']) . ']</strong>' : '';

            $details = [];
            if (!empty($change['old_hash']) && !empty($change['new_hash'])) {
                $details[] = '<strong>' . esc_html__('Hash:', 'advanced-ip-blocker') . '</strong> <code>' . esc_html(substr($change['old_hash'], 0, 8)) . '... &rarr; ' . esc_html(substr($change['new_hash'], 0, 8)) . '...</code>';
            } elseif (!empty($change['new_hash'])) {
                $details[] = '<strong>' . esc_html__('Hash:', 'advanced-ip-blocker') . '</strong> <code>' . esc_html(substr($change['new_hash'], 0, 8)) . '...</code>';
            }

            if (isset($change['new_size'])) {
                if (isset($change['old_size']) && $change['old_size'] !== null) {
                    $size_label = esc_html($this->format_file_size($change['old_size'])) . ' &rarr; ' . esc_html($this->format_file_size($change['new_size']));
                    if ((int) $change['old_size'] === (int) $change['new_size']) {
                        $size_label .= ' <em>(' . esc_html__('identical size, content/line-ending changed', 'advanced-ip-blocker') . ')</em>';
                    }
                    $details[] = '<strong>' . esc_html__('Size:', 'advanced-ip-blocker') . '</strong> ' . $size_label;
                } else {
                    $details[] = '<strong>' . esc_html__('Size:', 'advanced-ip-blocker') . '</strong> ' . esc_html($this->format_file_size($change['new_size']));
                }
            } elseif (isset($change['old_size']) && $change['old_size'] !== null) {
                $details[] = '<strong>' . esc_html__('Former Size:', 'advanced-ip-blocker') . '</strong> ' . esc_html($this->format_file_size($change['old_size']));
            }

            $details_html = '';
            if (!empty($details)) {
                $details_html = '<div style="margin: 4px 0 8px 14px; font-size: 12px; color: #555; line-height: 1.5;">' . implode('<br>', $details) . '</div>';
            }

            $badge_color = '#00a32a';
            if ($change['type'] === 'deleted') {
                $badge_color = '#dc3232';
            } elseif ($change['type'] === 'modified') {
                $badge_color = '#dba617';
            } elseif (strpos($change['type'], 'suspicious') !== false) {
                $badge_color = '#ff6600';
            }

            $body_content .= sprintf(
                '<li style="margin-bottom: 8px;"><strong>%s:</strong> <code>%s</code> <span style="display:inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; color: #fff; background-color: %s;">%s</span>%s%s</li>',
                __('File', 'advanced-ip-blocker'),
                esc_html($change['file']),
                $badge_color,
                strtoupper(str_replace('_', ' ', $change['type'])),
                $malware_info,
                $details_html
            );
        }
        $body_content .= '</ul>';

        $body_content .= '<p>' . esc_html__('Please review these files immediately. If you made these changes, no action is required.', 'advanced-ip-blocker') . '</p>';
        $body_content .= '<p><em>' . esc_html__('The baseline has been updated to these new versions.', 'advanced-ip-blocker') . '</em></p>';

        if (isset($this->main_instance->notification_manager)) {
            $fim_settings_url = admin_url('admin.php?page=advaipbl_settings_page&tab=settings&sub-tab=general_settings#section-internal_security');
            $body = $this->main_instance->notification_manager->get_html_email_template($template_title, $body_content, $fim_settings_url);

            add_filter('wp_mail_content_type', [$this->main_instance->notification_manager, 'set_html_mail_content_type']);
            wp_mail($to, $subject, $body);
            remove_filter('wp_mail_content_type', [$this->main_instance->notification_manager, 'set_html_mail_content_type']);

            if (!empty($this->main_instance->options['enable_push_notifications'])) {
                $push_message_lines = [
                    sprintf('*:file_folder: [%s] CRITICAL: File Change Detected*', $site_name),
                    '> The File Integrity Monitor has detected unauthorized changes to critical system files.',
                ];
                foreach ($change_summary as $summary_item) {
                    $push_message_lines[] = sprintf('> • *File:* %s', $summary_item);
                }
                $push_message_lines[] = sprintf('> • *Time:* %s', $date_time);
                $push_message_lines[] = sprintf('> • *Trigger:* %s', $trigger_source . $user_info);

                $this->main_instance->notification_manager->execute_webhook_send(implode("\n", $push_message_lines));
            }
        } else {
            $body = $body_content;
            wp_mail($to, $subject, $body);
        }
    }

    /**
     * Updates the baseline hash for a specific file.
     * Use this when the plugin legitimately modifies a monitored file.
     *
     * @param string $filepath Absolute path to the file.
     * @return bool True if updated, false otherwise.
     */
    public function update_file_hash($filepath)
    {
        if (empty($this->main_instance->options['enable_fim'])) {
            return false;
        }

        $baseline = get_option(self::OPTION_BASELINE_HASHES, []);
        if (empty($baseline)) {
            return false;
        }

        $normalized_input = wp_normalize_path($filepath);
        $monitored_files = $this->get_monitored_files();
        $key = false;

        foreach ($monitored_files as $file_key => $monitored_path) {
            if (wp_normalize_path($monitored_path) === $normalized_input) {
                $key = $file_key;
                break;
            }
        }

        if (!$key && (basename($normalized_input) === '.htaccess')) {
            $key = '.htaccess';
        }

        if (!$key) {
            return false;
        }

        $new_hash = $this->get_file_hash($filepath);
        if ($new_hash && $new_hash !== 'skipped_too_large') {
            $baseline[$key] = [
                'hash'      => $new_hash,
                'size'      => file_exists($filepath) ? filesize($filepath) : 0,
                'timestamp' => time(),
            ];
            update_option(self::OPTION_BASELINE_HASHES, $baseline);

            return true;
        }

        return false;
    }
}
