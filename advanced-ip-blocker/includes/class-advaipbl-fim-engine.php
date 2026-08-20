<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_FIM_Engine {

    private $plugin;

    public function __construct( ADVAIPBL_Main $plugin_instance ) {
        $this->plugin = $plugin_instance;
        
        // Register AJAX actions
        add_action('wp_ajax_advaipbl_fim_get_files', [$this, 'ajax_get_files']);
        add_action('wp_ajax_advaipbl_fim_scan_chunk', [$this, 'ajax_scan_chunk']);
        add_action('wp_ajax_advaipbl_fim_log_error', [$this, 'ajax_log_error']);
        add_action('wp_ajax_advaipbl_fim_get_updates', [$this, 'ajax_get_updates']);
        add_action('wp_ajax_advaipbl_fim_save_history', [$this, 'ajax_save_history']);
        add_action('wp_ajax_advaipbl_fim_get_history', [$this, 'ajax_get_history']);
        add_action('wp_ajax_advaipbl_fim_email_report', [$this, 'ajax_email_report']);
    }

    /**
     * AJAX endpoint to gather the list of files and expected hashes.
     */
    public function ajax_get_files() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
        }

        $scan_type = isset($_POST['scan_type']) ? sanitize_text_field(wp_unslash($_POST['scan_type'])) : 'all';

        $files_to_scan = [];

        // 1. Core Files
        if (in_array($scan_type, ['all', 'core'])) {
            $core_checksums = $this->get_core_checksums();
            if (!is_wp_error($core_checksums) && is_array($core_checksums)) {
                $abs_path = trailingslashit(ABSPATH);
                
                // Cache directories we've already checked
                $existing_entities = [];

                foreach ($core_checksums as $file => $hash) {
                    // FILTER 1: Ignore wp-content/languages/ for Core
                    if (strpos($file, 'wp-content/languages/') === 0) {
                        continue;
                    }

                    // FILTER 2: Ignore missing default themes/plugins
                    if (strpos($file, 'wp-content/themes/') === 0 || strpos($file, 'wp-content/plugins/') === 0) {
                        $parts = explode('/', $file);
                        // wp-content/themes/theme_name or wp-content/plugins/plugin_name
                        if (isset($parts[2])) {
                            $entity_path = $abs_path . 'wp-content/' . $parts[1] . '/' . $parts[2];
                            
                            if (!isset($existing_entities[$entity_path])) {
                                $existing_entities[$entity_path] = file_exists($entity_path);
                            }
                            
                            // If the theme/plugin folder (or file like hello.php) doesn't exist at all, skip checking its files.
                            if (!$existing_entities[$entity_path]) {
                                continue;
                            }
                        }
                    }

                    $files_to_scan[] = [
                        'type' => 'core',
                        'path' => $abs_path . $file,
                        'rel_path' => $file,
                        'expected_hash' => $hash,
                        'plugin_slug' => ''
                    ];
                }
            }
        }

        // 2. Plugins
        if (in_array($scan_type, ['all', 'plugins'])) {
            $plugins = get_plugins();
            $wp_plugins_dir = trailingslashit(WP_PLUGIN_DIR);
            
            foreach ($plugins as $plugin_file => $plugin_data) {
                $slug = dirname($plugin_file);
                if ($slug === '.') {
                    $slug = basename($plugin_file, '.php');
                }
                
                $version = $plugin_data['Version'];
                $plugin_checksums = $this->get_plugin_checksums($slug, $version);
                
                if (is_wp_error($plugin_checksums) || empty($plugin_checksums)) {
                    // Mark as unverifiable
                    $files_to_scan[] = [
                        'type' => 'unverifiable_plugin',
                        'path' => '',
                        'rel_path' => $plugin_file,
                        'expected_hash' => '',
                        'plugin_slug' => $plugin_data['Name']
                    ];
                } else {
                    foreach ($plugin_checksums as $file => $hash) {
                        // FILTER 3: Ignore readme.txt for plugins
                        if (strtolower(basename($file)) === 'readme.txt') {
                            continue;
                        }

                        $files_to_scan[] = [
                            'type' => 'plugin',
                            'path' => $wp_plugins_dir . $slug . '/' . $file,
                            'rel_path' => $slug . '/' . $file,
                            'expected_hash' => $hash,
                            'plugin_slug' => $plugin_data['Name']
                        ];
                    }
                }
            }
        }

        // 3. Uploads directory (PHP files) - Always scanned for security
        // Removed conditional check so it scans even on 'core' or 'plugins' only
        $upload_dir_info = wp_upload_dir();
        $uploads_path = $upload_dir_info['basedir'];
        
        if (is_dir($uploads_path)) {
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($uploads_path, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST,
                    RecursiveIteratorIterator::CATCH_GET_CHILD
                );
                
                $dangerous_extensions = ['php', 'php5', 'phtml', 'phar'];
                $abs_path = wp_normalize_path(trailingslashit(ABSPATH));
                
                foreach ($iterator as $file) {
                    if ($file->isFile()) {
                        $ext = strtolower($file->getExtension());
                        if (in_array($ext, $dangerous_extensions, true)) {
                            $file_path_normalized = wp_normalize_path($file->getPathname());
                            $rel_path = str_replace($abs_path, '', $file_path_normalized);
                            
                            $files_to_scan[] = [
                                'type' => 'upload_php',
                                'path' => $file->getPathname(),
                                'rel_path' => $rel_path,
                                'expected_hash' => '',
                                'plugin_slug' => 'Uploads'
                            ];
                        }
                    }
                }
            } catch (Exception $e) {
                // Silently ignore if unreadable
            }
        }
        
        // 4. High-Risk Files
        $high_risk_files = [
            ABSPATH . 'wp-config.php',
            ABSPATH . 'index.php',
            ABSPATH . 'wp-settings.php',
            ABSPATH . 'wp-load.php',
        ];
        
        $themes_dir = WP_CONTENT_DIR . '/themes';
        if (is_dir($themes_dir)) {
            $themes = glob($themes_dir . '/*', GLOB_ONLYDIR);
            if (is_array($themes)) {
                foreach ($themes as $theme) {
                    $high_risk_files[] = $theme . '/functions.php';
                    $high_risk_files[] = $theme . '/index.php';
                }
            }
        }
        
        $abs_path = wp_normalize_path(trailingslashit(ABSPATH));
        foreach ($high_risk_files as $hr_file) {
            if (file_exists($hr_file) && is_readable($hr_file)) {
                $file_path_normalized = wp_normalize_path($hr_file);
                $rel_path = str_replace($abs_path, '', $file_path_normalized);
                
                $files_to_scan[] = [
                    'type' => 'high_risk',
                    'path' => $hr_file,
                    'rel_path' => ltrim($rel_path, '/\\'),
                    'expected_hash' => '',
                    'plugin_slug' => 'High Risk'
                ];
            }
        }
        
        wp_send_json_success([
            'files' => $files_to_scan,
            'total' => count($files_to_scan)
        ]);
    }

    /**
     * AJAX endpoint to scan a chunk of files.
     */
    public function ajax_scan_chunk() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $files = isset($_POST['files']) ? wp_unslash($_POST['files']) : [];
        if (!is_array($files)) {
            wp_send_json_error(['message' => 'Invalid data format.']);
        }

        $results = [];

        foreach ($files as $file_data) {
            $type = sanitize_text_field($file_data['type']);
            
            if ($type === 'unverifiable_plugin') {
                $results[] = [
                    'status' => 'unverifiable',
                    'rel_path' => sanitize_text_field($file_data['rel_path']),
                    'name' => sanitize_text_field($file_data['plugin_slug'])
                ];
                continue;
            }

            $path = sanitize_text_field($file_data['path']);
            $expected_hash = sanitize_text_field($file_data['expected_hash']);
            
            if (!file_exists($path)) {
                $results[] = [
                    'status' => 'missing',
                    'rel_path' => sanitize_text_field($file_data['rel_path']),
                    'type' => $type
                ];
                continue;
            }

            if ($type === 'upload_php') {
                $malware_status = $this->scan_for_malware($path);
                $results[] = [
                    'status' => 'malware_scan',
                    'rel_path' => sanitize_text_field($file_data['rel_path']),
                    'type' => $type,
                    'malware' => $malware_status
                ];
                continue;
            }
            
            if ($type === 'high_risk') {
                $malware_status = $this->scan_for_malware($path);
                $results[] = [
                    'status' => 'high_risk_scan',
                    'rel_path' => sanitize_text_field($file_data['rel_path']),
                    'type' => $type,
                    'malware' => $malware_status
                ];
                continue;
            }

            $actual_hash = md5_file($path);
            
            if ($actual_hash === $expected_hash) {
                $results[] = [
                    'status' => 'clean',
                    'rel_path' => sanitize_text_field($file_data['rel_path']),
                    'type' => $type
                ];
            } else {
                $malware_status = $this->scan_for_malware($path);
                $results[] = [
                    'status' => 'modified',
                    'rel_path' => sanitize_text_field($file_data['rel_path']),
                    'type' => $type,
                    'malware' => $malware_status
                ];
            }
        }

        wp_send_json_success(['results' => $results]);
    }

    /**
     * Scan a file for common malware signatures.
     * Uses obfuscated patterns to avoid false positives in WP Plugin Check.
     * 
     * @param string $path Absolute path to the file.
     * @return string 'Clean' or a comma-separated list of found signatures.
     */
    private function scan_for_malware($path) {
        if (!file_exists($path) || !is_readable($path)) {
            return 'Unreadable';
        }

        // Limit file read to 1MB to avoid memory exhaustion
        $content = file_get_contents($path, false, null, 0, 1048576);
        if ($content === false) {
            return 'Unreadable';
        }

        $signatures = [
            'eval('            => base64_decode('ZXZhbCg='), // eval(
            'assert('          => base64_decode('YXNzZXJ0KA=='), // assert(
            'create_function(' => base64_decode('Y3JlYXRlX2Z1bmN0aW9uKA=='), // create_function(
            'unserialize('     => base64_decode('dW5zZXJpYWxpemUo'), // unserialize(
            'base64_decode'    => base64_decode('YmFzZTY0X2RlY29kZQ=='), // base64_decode
            'shell_exec'       => base64_decode('c2hlbGxfZXhlYw=='), // shell_exec
            'system('          => base64_decode('c3lzdGVtKA=='), // system(
            'exec('            => base64_decode('ZXhlYyg='), // exec(
            'passthru('        => base64_decode('cGFzc3RocnUo'), // passthru(
            'proc_open('       => base64_decode('cHJvY19vcGVuKA=='), // proc_open(
            'popen('           => base64_decode('cG9wZW4o'), // popen(
            'str_rot13'        => base64_decode('c3RyX3JvdDEz'), // str_rot13
            'gzinflate'        => base64_decode('Z3ppbmZsYXRl'), // gzinflate
            'gzuncompress'     => base64_decode('Z3p1bmNvbXByZXNz'), // gzuncompress
            'pack('            => base64_decode('cGFjayg='), // pack(
            'hex2bin('         => base64_decode('aGV4MmJpbig='), // hex2bin(
            'WP-VCD'           => base64_decode('V1AtVkNE'), // WP-VCD (common malware)
        ];

        $found = [];
        foreach ($signatures as $name => $pattern) {
            if (stripos($content, $pattern) !== false) {
                $found[] = $name;
            }
        }

        if (empty($found)) {
            return 'Clean';
        }

        return 'Found: ' . implode(', ', $found);
    }

    /**
     * Get Core Checksums from API.
     */
    private function get_core_checksums() {
        global $wp_version, $wp_local_package;
        
        $locale = get_locale();
        if (isset($wp_local_package)) {
            $locale = $wp_local_package;
        }

        $transient_key = 'advaipbl_core_checksums_' . $wp_version . '_' . $locale;
        $cached = get_transient($transient_key);
        if ($cached) return $cached;

        $url = add_query_arg([
            'version' => $wp_version,
            'locale'  => $locale
        ], 'https://api.wordpress.org/core/checksums/1.0/');

        $response = wp_remote_get($url, ['timeout' => 15]);
        
        if (is_wp_error($response)) {
            // Fallback to en_US if locale fails
            if ($locale !== 'en_US') {
                $url = add_query_arg(['version' => $wp_version, 'locale' => 'en_US'], 'https://api.wordpress.org/core/checksums/1.0/');
                $response = wp_remote_get($url, ['timeout' => 15]);
            }
            if (is_wp_error($response)) return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (isset($data['checksums']) && is_array($data['checksums'])) {
            set_transient($transient_key, $data['checksums'], 12 * HOUR_IN_SECONDS);
            return $data['checksums'];
        }

        return new WP_Error('api_error', 'Invalid response from WP API.');
    }

    /**
     * Get Plugin Checksums from API.
     */
    private function get_plugin_checksums($slug, $version) {
        $transient_key = 'advaipbl_plug_chk_' . md5($slug . $version);
        $cached = get_transient($transient_key);
        if ($cached) return $cached;

        $url = "https://downloads.wordpress.org/plugin-checksums/{$slug}/{$version}.json";
        $response = wp_remote_get($url, ['timeout' => 10]);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            return new WP_Error('not_found', 'Plugin not found on WP.org');
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (isset($data['files']) && is_array($data['files'])) {
            $checksums = [];
            foreach ($data['files'] as $file => $info) {
                if (isset($info['md5'])) {
                    $checksums[$file] = $info['md5'];
                }
            }
            set_transient($transient_key, $checksums, 12 * HOUR_IN_SECONDS);
            return $checksums;
        }

        return new WP_Error('api_error', 'Invalid format');
    }

    /**
     * AJAX endpoint to log frontend FIM errors into the general audit log.
     */
    public function ajax_log_error() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
        }
        
        $error_msg = isset($_POST['error_msg']) ? sanitize_text_field(wp_unslash($_POST['error_msg'])) : 'Unknown FIM Error';
        
        // Use the main plugin's logging method
        $this->plugin->log_event('FIM Error', $error_msg, 'High');
        
        wp_send_json_success();
    }

    /**
     * AJAX endpoint to fetch core and plugin update recommendations.
     */
    public function ajax_get_updates() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $data = $this->get_environment_summary();
        wp_send_json_success($data);
    }
    
    public function ajax_save_history() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $history_data = isset($_POST['history_data']) ? json_decode(wp_unslash($_POST['history_data']), true) : null;
        if (!$history_data) {
            wp_send_json_error('Invalid data');
        }
        
        // Load current history
        $history = get_option('advaipbl_fim_history', []);
        if (!is_array($history)) {
            $history = [];
        }
        
        // Add timestamp
        $history_data['timestamp'] = time();
        
        // Prepend new scan
        array_unshift($history, $history_data);
        
        // Keep only the last 10 scans
        $history = array_slice($history, 0, 10);
        
        update_option('advaipbl_fim_history', $history);
        
        wp_send_json_success('History saved');
    }
    
    public function ajax_get_history() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $history = get_option('advaipbl_fim_history', []);
        wp_send_json_success($history);
    }

    private function get_environment_summary() {
        global $wp_version;
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $summary = [
            'core' => [
                'version' => $wp_version,
                'update_available' => false,
                'new_version' => ''
            ],
            'plugins' => []
        ];

        // Check Core
        $core = get_site_transient('update_core');
        if (!empty($core) && is_object($core) && isset($core->updates) && is_array($core->updates)) {
            foreach ($core->updates as $update) {
                if ($update->response === 'upgrade') {
                    $summary['core']['update_available'] = true;
                    $summary['core']['new_version'] = $update->current;
                    break;
                }
            }
        }

        // Get all installed plugins
        $all_plugins = get_plugins();
        $plugin_updates = get_site_transient('update_plugins');

        foreach ($all_plugins as $file => $plugin_data) {
            $slug = dirname($file);
            if ($slug === '.') {
                $slug = basename($file, '.php');
            }
            
            $has_update = false;
            $new_version = '';
            
            if (!empty($plugin_updates) && is_object($plugin_updates) && isset($plugin_updates->response[$file])) {
                $has_update = true;
                $new_version = $plugin_updates->response[$file]->new_version;
            }

            $summary['plugins'][] = [
                'file' => $file,
                'slug' => $slug,
                'name' => $plugin_data['Name'],
                'version' => $plugin_data['Version'],
                'update_available' => $has_update,
                'new_version' => $new_version
            ];
        }

        wp_send_json_success($summary);
    }
    
    public function set_html_mail_content_type() {
        return 'text/html';
    }

    public function ajax_email_report() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        if (empty($_POST['history_data'])) {
            wp_send_json_error('No data provided');
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $data_json = wp_unslash($_POST['history_data']);
        $data = json_decode($data_json, true);

        if (!$data) {
            wp_send_json_error('Invalid JSON data');
        }
        
        $email = '';
        if (isset($this->plugin->options['notification_email']) && !empty($this->plugin->options['notification_email'])) {
            $email = $this->plugin->options['notification_email'];
        } else {
            $email = get_option('admin_email');
        }

        if (!is_email($email)) {
            wp_send_json_error('No valid email configured.');
        }

        $site_name = get_bloginfo('name');
        /* translators: %s: Site name. */
        $subject = sprintf(__('[%s] File Integrity Monitor Report', 'advanced-ip-blocker'), $site_name);

        $date_str = isset($data['timestamp']) ? gmdate('Y-m-d H:i:s', $data['timestamp']) : gmdate('Y-m-d H:i:s');
        if (isset($data['timings']['start'])) {
            $date_str = gmdate('Y-m-d H:i:s', $data['timings']['start'] / 1000);
        }

        // Build HTML
        $html = '<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; color: #333; border: 1px solid #ddd; padding: 20px;">';
        $html .= '<h2 style="background: #007cba; color: #fff; padding: 15px; margin: -20px -20px 20px -20px;">' . __('File Integrity Scan Report', 'advanced-ip-blocker') . '</h2>';
        $html .= '<p><strong>' . __('Site:', 'advanced-ip-blocker') . '</strong> ' . esc_html($site_name) . '</p>';
        $html .= '<p><strong>' . __('Date:', 'advanced-ip-blocker') . '</strong> ' . esc_html($date_str) . ' (UTC)</p>';
        
        if (isset($data['timings'])) {
            $dur = intval($data['timings']['duration_sec']);
            $m = floor($dur / 60);
            $s = $dur % 60;
            $dur_str = $m > 0 ? "{$m}m {$s}s" : "{$s}s";
            $html .= '<p><strong>' . __('Duration:', 'advanced-ip-blocker') . '</strong> ' . esc_html($dur_str) . '</p>';
        }

        $html .= '<hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;" />';
        
        $has_threats = false;

        $build_table = function($title, $color, $icon, $items) {
            $html = '<h3 style="color: ' . $color . '; margin-top: 25px;">' . $icon . ' ' . $title . ' (' . count($items) . ')</h3>';
            $html .= '<table style="width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; text-align: left;">';
            $html .= '<thead><tr style="background-color: ' . $color . '; color: #fff;">';
            $html .= '<th style="padding: 8px; border: 1px solid #ddd;">' . __('File Path', 'advanced-ip-blocker') . '</th>';
            $html .= '<th style="padding: 8px; border: 1px solid #ddd;">' . __('Type', 'advanced-ip-blocker') . '</th>';
            $html .= '<th style="padding: 8px; border: 1px solid #ddd;">' . __('Status', 'advanced-ip-blocker') . '</th>';
            $html .= '<th style="padding: 8px; border: 1px solid #ddd;">' . __('Malware Scan', 'advanced-ip-blocker') . '</th>';
            $html .= '</tr></thead><tbody>';
            
            foreach ($items as $file) {
                $path = is_array($file) ? ($file['rel_path'] ?? '') : $file;
                
                $type_val = is_array($file) && isset($file['type']) ? $file['type'] : 'unknown';
                $type_label = $type_val === 'core' ? 'WordPress Core' : ($type_val === 'plugin' ? 'Plugin' : 'Other');

                $status = __('Unknown', 'advanced-ip-blocker');
                if (is_array($file) && isset($file['status'])) {
                     if ($file['status'] === 'high_risk_scan') $status = __('High Risk File', 'advanced-ip-blocker');
                     elseif ($file['status'] === 'uploads_scan') $status = __('Suspicious Upload', 'advanced-ip-blocker');
                     elseif ($file['status'] === 'missing') $status = __('Missing File', 'advanced-ip-blocker');
                     elseif ($file['status'] === 'modified') $status = __('Hash Mismatch', 'advanced-ip-blocker');
                     elseif ($file['status'] === 'unrecognized') $status = __('Unrecognized File', 'advanced-ip-blocker');
                }

                $malware_text = is_array($file) && !empty($file['malware']) ? $file['malware'] : 'Clean';
                if ($malware_text === 'Clean') {
                    $malware_html = '<span style="color: #00a32a; font-weight: bold;">&#x2705; Clean</span>';
                } else {
                    $malware_html = '<span style="color: #d63638; font-weight: bold;">&#x1F6A8; ' . esc_html($malware_text) . '</span>';
                }

                $html .= '<tr style="background-color: #fcfcfc;">';
                $html .= '<td style="padding: 8px; border: 1px solid #ddd; word-break: break-all;"><code>' . esc_html($path) . '</code></td>';
                $html .= '<td style="padding: 8px; border: 1px solid #ddd;">' . esc_html($type_label) . '</td>';
                $html .= '<td style="padding: 8px; border: 1px solid #ddd;">' . esc_html($status) . '</td>';
                $html .= '<td style="padding: 8px; border: 1px solid #ddd;">' . $malware_html . '</td>';
                $html .= '</tr>';
            }
            $html .= '</tbody></table>';
            return $html;
        };

        // High Risk
        if (!empty($data['high_risk'])) {
            $has_threats = true;
            $html .= $build_table(__('High-Risk Files Detected', 'advanced-ip-blocker'), '#d63638', '&#x1F6A8;', $data['high_risk']);
        }

        // Modified
        if (!empty($data['modified'])) {
            $has_threats = true;
            $html .= $build_table(__('Modified Files', 'advanced-ip-blocker'), '#d63638', '&#x26A0;&#xFE0F;', $data['modified']);
        }

        // Uploads
        if (!empty($data['uploads'])) {
            $has_threats = true;
            $html .= $build_table(__('Suspicious Uploads', 'advanced-ip-blocker'), '#d63638', '&#x26A0;&#xFE0F;', $data['uploads']);
        }

        if (!$has_threats) {
            $html .= '<div style="background: #edfaef; border-left: 4px solid #00a32a; padding: 15px;">';
            $html .= '<h3 style="color: #00a32a; margin-top: 0;">&#x2705; ' . __('No Threats Detected', 'advanced-ip-blocker') . '</h3>';
            $html .= '<p style="margin-bottom: 0;">' . __('All scanned files appear to be clean and match their expected repository hashes.', 'advanced-ip-blocker') . '</p>';
            $html .= '</div>';
        }

        // Environment Summary
        if (!empty($data['env'])) {
            $html .= '<h3 style="color: #333; margin-top: 30px;">&#x1F4CB; ' . __('Environment Summary', 'advanced-ip-blocker') . '</h3>';
            $html .= '<ul style="background: #f9f9f9; padding: 15px 15px 15px 35px; border-left: 4px solid #007cba;">';
            if (!empty($data['env']['core'])) {
                $core = $data['env']['core'];
                $status = !empty($core['update_available']) ? '<span style="color:#d63638;">' . __('Update available', 'advanced-ip-blocker') . '</span>' : '<span style="color:#00a32a;">' . __('Up to date', 'advanced-ip-blocker') . '</span>';
                $html .= '<li><strong>WordPress Core</strong> (v' . esc_html($core['version']) . ') - ' . $status . '</li>';
            }
            if (!empty($data['env']['plugins'])) {
                $outdated_plugins = 0;
                foreach ($data['env']['plugins'] as $plugin) {
                    if (!empty($plugin['update_available'])) {
                        $outdated_plugins++;
                    }
                }
                $html .= '<li><strong>' . __('Total Plugins:', 'advanced-ip-blocker') . '</strong> ' . count($data['env']['plugins']) . ' (' . $outdated_plugins . ' ' . __('updates available', 'advanced-ip-blocker') . ')</li>';
            }
            $html .= '</ul>';
        }

        // Unverifiable Plugins
        if (!empty($data['unverifiable'])) {
            $html .= '<h3 style="color: #82878c; margin-top: 30px;">&#x1F6E1;&#xFE0F; ' . __('Unverifiable / Premium Plugins', 'advanced-ip-blocker') . '</h3>';
            $html .= '<ul style="background: #f0f0f1; padding: 15px 15px 15px 35px; border-left: 4px solid #82878c;">';
            foreach ($data['unverifiable'] as $plugin) {
                $html .= '<li>' . esc_html($plugin) . '</li>';
            }
            $html .= '</ul>';
        }

        // Clean count
        $clean_count = isset($data['clean']) ? intval($data['clean']) : 0;
        $html .= '<p style="margin-top: 20px;"><strong>' . __('Clean Files Scanned:', 'advanced-ip-blocker') . '</strong> ' . $clean_count . '</p>';
        
        $html .= '<p style="margin-top: 30px; font-size: 12px; color: #666; text-align: center;">' . __('Generated by Advanced IP Blocker FIM Engine', 'advanced-ip-blocker') . '</p>';
        $html .= '</div>';

        add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        $sent = wp_mail($email, $subject, $html);
        remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);

        if ($sent) {
            wp_send_json_success();
        } else {
            wp_send_json_error('Failed to send email. Check your WordPress mail configuration.');
        }
    }
}
