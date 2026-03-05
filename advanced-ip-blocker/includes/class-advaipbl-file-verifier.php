<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_File_Verifier {

    private $main_instance;
    const OPTION_BASELINE_HASHES = 'advaipbl_fim_baseline_hashes';

    public function __construct($main_instance) {
        $this->main_instance = $main_instance;
    }

    /**
     * Calculates the hash of a critical file.
     * 
     * @param string $filepath Absolute path to the file.
     * @return string|false SHA-256 hash or false if file not found.
     */
    public function get_file_hash($filepath) {
        if (!file_exists($filepath)) {
            return false;
        }
         // 2MB limit to avoid memory issues
        if (filesize($filepath) > 2 * 1024 * 1024) {
            return 'skipped_too_large';
        }
        return hash_file('sha256', $filepath);
    }

    /**
     * Gets the list of critical files to monitor.
     * @return array
     */
    public function get_monitored_files() {
        return [
            'wp-config.php' => ABSPATH . 'wp-config.php',
            'index.php'     => ABSPATH . 'index.php',
            'wp-settings.php'=> ABSPATH . 'wp-settings.php',
            '.htaccess'     => ABSPATH . '.htaccess',
        ];
    }

    /**
     * Creates and stores the initial baseline hashes.
     */
    public function create_baseline() {
        $baseline = [];
        foreach ($this->get_monitored_files() as $key => $path) {
            $hash = $this->get_file_hash($path);
            if ($hash && $hash !== 'skipped_too_large') {
                $baseline[$key] = [
                    'hash' => $hash,
                    'timestamp' => time()
                ];
            }
        }
        update_option(self::OPTION_BASELINE_HASHES, $baseline);
        return $baseline;
    }

    /**
     * Scans files against the stored baseline.
     * @return array List of changed files.
     */
    public function scan_files() {
        // Double check setting
        if (empty($this->main_instance->options['enable_fim'])) {
            return [];
        }

        $baseline = get_option(self::OPTION_BASELINE_HASHES, []);
        if (empty($baseline)) {
            // First run, create baseline
            $this->create_baseline();
            return [];
        }

        $changes = [];
        foreach ($this->get_monitored_files() as $key => $path) {
            $current_hash = $this->get_file_hash($path);
            
            // If file existed in baseline but now gone/unreadable
            if (!$current_hash && isset($baseline[$key])) {
                $changes[] = [
                    'file' => $key,
                    'type' => 'deleted'
                ];
                continue;
            }

            // If file exists and we have a baseline
            if ($current_hash && isset($baseline[$key])) {
                if ($current_hash !== $baseline[$key]['hash']) {
                    $changes[] = [
                        'file' => $key,
                        'type' => 'modified',
                        'old_hash' => $baseline[$key]['hash'],
                        'new_hash' => $current_hash
                    ];
                }
            } else if ($current_hash && !isset($baseline[$key])) {
                // Should not happen with fixed list, but good for future dynamic lists
                $changes[] = [
                   'file' => $key,
                   'type' => 'added',
                   'new_hash' => $current_hash
                ];
            }
        }

        if (!empty($changes)) {
            $this->handle_fim_alert($changes);
            
            // Update baseline to prevent repeated alerts for the same change?
            // SECURITY DECISION: No, we keep alerting until manual reset? 
            // Better: update the specific files in baseline so we detect *new* changes.
            foreach ($changes as $change) {
                if ($change['type'] === 'modified' || $change['type'] === 'added') {
                    $baseline[$change['file']] = ['hash' => $change['new_hash'], 'timestamp' => time()];
                } elseif ($change['type'] === 'deleted') {
                    unset($baseline[$change['file']]);
                }
            }
            update_option(self::OPTION_BASELINE_HASHES, $baseline);
        }

        return $changes;
    }

    private function handle_fim_alert($changes) {
        $change_summary = [];
        foreach ($changes as $change) {
            $change_summary[] = "{$change['file']} ({$change['type']})";
        }
        $summary_string = implode(', ', $change_summary);
        
        // Use Audit Logger instead of generic log
        if (isset($this->main_instance->audit_logger)) {
            $this->main_instance->audit_logger->log_activity(
                'fim_alert', 
                'critical', 
                ['message' => 'File integrity changes detected', 'files' => $change_summary]
            );
        } else {
            // Fallback
            $this->main_instance->log_event('File Integrity Monitor detected changes: ' . wp_json_encode($changes), 'critical');
        }
        
        $to = !empty($this->main_instance->options['fim_alert_email']) 
            ? $this->main_instance->options['fim_alert_email'] 
            : get_option('admin_email');
            
        $site_name = get_bloginfo('name');
        
        /* translators: %s: Site name */
        $subject = sprintf(__('[%s] CRITICAL: File Change Detected', 'advanced-ip-blocker'), $site_name);
        
        $template_title = __('File Integrity Alert', 'advanced-ip-blocker');
        
        // Context Data
        $date_time = date_i18n(get_option('date_format') . ' ' . get_option('time_format'));
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : 'Unknown';
        
        // Trigger detection
        $trigger_source = 'Scheduled Cron';
        $user_info = '';
        
        if (is_admin() && current_user_can('manage_options') && wp_doing_ajax()) {
            $current_user = wp_get_current_user();
            $trigger_source = 'Manual Scan';
            $user_info = sprintf(' (%s)', $current_user->user_login);
        }

        $body_content = '<p><strong>' . esc_html__('Detection Time:', 'advanced-ip-blocker') . '</strong> ' . esc_html($date_time) . '<br>';
        $body_content .= '<strong>' . esc_html__('Server IP:', 'advanced-ip-blocker') . '</strong> ' . esc_html($server_ip) . '<br>';
        $body_content .= '<strong>' . esc_html__('Trigger:', 'advanced-ip-blocker') . '</strong> ' . esc_html($trigger_source . $user_info) . '</p>';

        $body_content .= '<hr style="border: 0; border-top: 1px solid #eee; margin: 15px 0;">';

        $body_content .= '<p>' . esc_html__('The Advanced IP Blocker File Integrity Monitor has detected unauthorized changes to critical system files:', 'advanced-ip-blocker') . '</p>';
        $body_content .= '<ul>';
        
        foreach ($changes as $change) {
            $body_content .= sprintf(
                '<li><strong>%s:</strong> %s <span style="color:%s;">(%s)</span></li>',
                __('File', 'advanced-ip-blocker'),
                esc_html($change['file']),
                $change['type'] === 'deleted' ? '#dc3232' : ($change['type'] === 'modified' ? '#dba617' : '#00a32a'),
                strtoupper($change['type'])
            );
        }
        $body_content .= '</ul>';
        
        $body_content .= '<p>' . esc_html__('Please review these files immediately. If you made these changes, no action is required.', 'advanced-ip-blocker') . '</p>';
        $body_content .= '<p><em>' . esc_html__('The baseline has been updated to these new versions.', 'advanced-ip-blocker') . '</em></p>';

        // Use the main HTML template (Delegated to Notification Manager)
        if (isset($this->main_instance->notification_manager)) {
            $body = $this->main_instance->notification_manager->get_html_email_template($template_title, $body_content);
            
            add_filter('wp_mail_content_type', [$this->main_instance->notification_manager, 'set_html_mail_content_type']);
            wp_mail($to, $subject, $body);
            remove_filter('wp_mail_content_type', [$this->main_instance->notification_manager, 'set_html_mail_content_type']);
            
             // --- Push Notification (New in 8.7.4) ---
            if (!empty($this->main_instance->options['enable_push_notifications'])) {
                $push_message_lines = [
                    sprintf('*:file_folder: [%s] CRITICAL: File Change Detected*', $site_name),
                    '> The File Integrity Monitor has detected unauthorized changes to critical system files.',
                    sprintf('> • *Files:* %s', implode(', ', $change_summary)),
                    sprintf('> • *Time:* %s', $date_time),
                    sprintf('> • *Trigger:* %s', $trigger_source . $user_info),
                ];
                $this->main_instance->notification_manager->execute_webhook_send(implode("\n", $push_message_lines));
            }
        } else {
             // Fallback if notification manager is missing
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
    public function update_file_hash($filepath) {
        // Double check setting
        if (empty($this->main_instance->options['enable_fim'])) {
            return false;
        }

        $baseline = get_option(self::OPTION_BASELINE_HASHES, []);
        if (empty($baseline)) {
            return false; // No baseline to update
        }

        // Find the key for this filepath
        $monitored_files = $this->get_monitored_files();
        $key = array_search($filepath, $monitored_files);

        if (!$key) {
            return false; // File not monitored
        }

        $new_hash = $this->get_file_hash($filepath);
        if ($new_hash && $new_hash !== 'skipped_too_large') {
            $baseline[$key] = [
                'hash' => $new_hash,
                'timestamp' => time()
            ];
            update_option(self::OPTION_BASELINE_HASHES, $baseline);
            return true;
        }

        return false;
    }
}
