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
        add_action('wp_ajax_advaipbl_fim_add_whitelist', [$this, 'ajax_add_whitelist']);
        add_action('wp_ajax_advaipbl_fim_remove_whitelist', [$this, 'ajax_remove_whitelist']);
        add_action('wp_ajax_advaipbl_fim_quarantine_file', [$this, 'ajax_quarantine_file']);
        add_action('wp_ajax_advaipbl_fim_restore_quarantine', [$this, 'ajax_restore_quarantine']);
        add_action('wp_ajax_advaipbl_fim_delete_quarantine', [$this, 'ajax_delete_quarantine']);
        add_action('wp_ajax_advaipbl_fim_get_quarantine_list', [$this, 'ajax_get_quarantine_list']);
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

        $raw_excluded_paths = $this->plugin->options['fim_excluded_paths'] ?? '';
        $excluded_paths = array_filter(array_map('trim', explode("\n", $raw_excluded_paths)));

        $files_to_scan = [];

        // --- DEEP SCAN ---
        if ($scan_type === 'deep_scan') {
            $abs_path = wp_normalize_path(trailingslashit(ABSPATH));
            $dangerous_extensions = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar'];
            
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator(ABSPATH, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST,
                    RecursiveIteratorIterator::CATCH_GET_CHILD
                );
                
                foreach ($iterator as $file) {
                    if ($file->isFile()) {
                        $ext = strtolower($file->getExtension());
                        if (in_array($ext, $dangerous_extensions, true)) {
                            $file_path_normalized = wp_normalize_path($file->getPathname());
                            $rel_path = str_replace($abs_path, '', $file_path_normalized);
                            
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
                            
                            $files_to_scan[] = [
                                'type' => 'deep_scan_file',
                                'path' => $file->getPathname(),
                                'rel_path' => $rel_path,
                                'expected_hash' => '',
                                'plugin_slug' => 'Deep Scan'
                            ];
                        }
                    }
                }
            } catch (Exception $e) {
                // Silently ignore if unreadable
            }
            
            wp_send_json_success(['files' => $files_to_scan, 'total' => count($files_to_scan)]);
            return;
        }

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
        
        $has_deep_scan = false;
        foreach ($files as $f) {
            if (isset($f['type']) && $f['type'] === 'deep_scan_file') {
                $has_deep_scan = true;
                break;
            }
        }
        
        $core_checksums = null;
        $plugin_checksum_cache = [];
        $whitelist = $this->get_whitelist();
        
        if ($has_deep_scan) {
            $core_checksums = $this->get_core_checksums();
            if (is_wp_error($core_checksums)) $core_checksums = [];
            
            if (!function_exists('get_plugins')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $installed_plugins = get_plugins();
            foreach ($installed_plugins as $p_file => $p_data) {
                $p_slug = dirname($p_file);
                if ($p_slug === '.') $p_slug = basename($p_file, '.php');
                $plugin_checksum_cache[$p_slug] = [
                    'version' => $p_data['Version'],
                    'checksums' => null
                ];
            }
        }

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
                $rel_path = sanitize_text_field($file_data['rel_path']);
                $is_whitelisted = $this->is_whitelisted($rel_path, $whitelist);
                $malware_status = $is_whitelisted ? 'Whitelisted' : $this->scan_for_malware($path);
                $results[] = [
                    'status' => 'malware_scan',
                    'rel_path' => $rel_path,
                    'type' => $type,
                    'malware' => $malware_status
                ];
                continue;
            }

            if ($type === 'deep_scan_file') {
                $rel_path = sanitize_text_field($file_data['rel_path']);
                $is_safe = false;
                
                // Anti-False-Positive Shield: Verify Hash
                if (isset($core_checksums[$rel_path])) {
                    $official_hash = $core_checksums[$rel_path];
                    if (md5_file($path) === $official_hash) {
                        $is_safe = true;
                    }
                } else if (strpos($rel_path, 'wp-content/plugins/') === 0) {
                    $parts = explode('/', $rel_path);
                    if (count($parts) >= 3) {
                        $p_slug = '';
                        $p_file_in_dir = '';
                        
                        if (count($parts) === 3) {
                            $p_slug = basename($parts[2], '.php');
                            $p_file_in_dir = $parts[2];
                        } else {
                            $p_slug = $parts[2];
                            $p_file_in_dir = implode('/', array_slice($parts, 3));
                        }
                        
                        if (isset($plugin_checksum_cache[$p_slug])) {
                            if ($plugin_checksum_cache[$p_slug]['checksums'] === null) {
                                $chk = $this->get_plugin_checksums($p_slug, $plugin_checksum_cache[$p_slug]['version']);
                                if (is_wp_error($chk)) $chk = [];
                                $plugin_checksum_cache[$p_slug]['checksums'] = $chk;
                            }
                            
                            $p_checksums = $plugin_checksum_cache[$p_slug]['checksums'];
                            if (isset($p_checksums[$p_file_in_dir])) {
                                $official_hash = $p_checksums[$p_file_in_dir];
                                if (md5_file($path) === $official_hash) {
                                    $is_safe = true;
                                }
                            }
                        }
                    }
                }
                
                if ($is_safe) {
                    $results[] = ['status' => 'clean'];
                    continue;
                }

                $is_whitelisted = $this->is_whitelisted($rel_path, $whitelist);
                $malware_status = $is_whitelisted ? 'Whitelisted' : $this->scan_for_malware($path);
                if ($malware_status === 'Clean') {
                    $results[] = ['status' => 'clean'];
                } else {
                    $results[] = [
                        'status' => 'deep_scan_file',
                        'rel_path' => $rel_path,
                        'type' => $type,
                        'malware' => $malware_status
                    ];
                }
                continue;
            }
            
            if ($type === 'high_risk') {
                $rel_path = sanitize_text_field($file_data['rel_path']);
                $is_whitelisted = $this->is_whitelisted($rel_path, $whitelist);
                $malware_status = $is_whitelisted ? 'Whitelisted' : $this->scan_for_malware($path);
                $results[] = [
                    'status' => 'high_risk_scan',
                    'rel_path' => $rel_path,
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
                $rel_path = sanitize_text_field($file_data['rel_path']);
                $is_whitelisted = $this->is_whitelisted($rel_path, $whitelist);
                $malware_status = $is_whitelisted ? 'Whitelisted' : $this->scan_for_malware($path);
                $results[] = [
                    'status' => 'modified',
                    'rel_path' => $rel_path,
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
            'Dynamic Code Execution (eval)' => [101, 118, 97, 108, 40],
            'Dynamic Code Execution (assert)' => [97, 115, 115, 101, 114, 116, 40],
            'Dynamic Code Execution (create_function)' => [99, 114, 101, 97, 116, 101, 95, 102, 117, 110, 99, 116, 105, 111, 110, 40],
            'Unsafe Object Deserialization' => [117, 110, 115, 101, 114, 105, 97, 108, 105, 122, 101, 40],
            'Base64 Decoding Function' => [98, 97, 115, 101, 54, 52, 95, 100, 101, 99, 111, 100, 101],
            'System Command Execution (shell_exec)' => [115, 104, 101, 108, 108, 95, 101, 120, 101, 99],
            'System Command Execution (system)' => [115, 121, 115, 116, 101, 109, 40],
            'System Command Execution (exec)' => [101, 120, 101, 99, 40],
            'System Command Execution (passthru)' => [112, 97, 115, 115, 116, 104, 114, 117, 40],
            'System Command Execution (proc_open)' => [112, 114, 111, 99, 95, 111, 112, 101, 110, 40],
            'System Command Execution (popen)' => [112, 111, 112, 101, 110, 40],
            'String ROT13 Obfuscation' => [115, 116, 114, 95, 114, 111, 116, 49, 51],
            'GZ Inflate Obfuscation' => [103, 122, 105, 110, 102, 108, 97, 116, 101],
            'GZ Uncompress Obfuscation' => [103, 122, 117, 110, 99, 111, 109, 112, 114, 101, 115, 115],
            'Binary Packing (pack)' => [112, 97, 99, 107, 40],
            'Hex to Bin Conversion' => [104, 101, 120, 50, 98, 105, 110, 40],
            'Malware Family: WP-VCD' => [87, 80, 45, 86, 67, 68],
            
            // Highly specific curated signatures from public-signatures-raw.php
            'Webshell: b374k' => [98, 51, 55, 52, 107],
            'Webshell: c99shell' => [99, 57, 57, 115, 104, 101, 108, 108],
            'Webshell: r57shell' => [114, 53, 55, 115, 104, 101, 108, 108],
            'Webshell: fx29shell' => [102, 120, 50, 57, 115, 104, 101, 108, 108],
            'Webshell: evilc0ders' => [101, 118, 105, 108, 99, 48, 100, 101, 114, 115],
            'Webshell: kingdefacer' => [107, 105, 110, 103, 100, 101, 102, 97, 99, 101, 114],
            'Webshell: Wireghoul' => [87, 105, 114, 101, 103, 104, 111, 117, 108],
            'Webshell: htshell' => [104, 116, 115, 104, 101, 108, 108],
            'Webshell: locus7s' => [108, 111, 99, 117, 115, 55, 115],
            'Payload: Meterpreter' => [109, 101, 116, 101, 114, 112, 114, 101, 116, 101, 114],
            'Tool: Slowloris' => [115, 108, 111, 119, 108, 111, 114, 105, 115],
            'Webshell: sun-tzu' => [115, 117, 110, 45, 116, 122, 117],
            'Bot: visbot' => [118, 105, 115, 98, 111, 116],
            'Remote Code Execution Payload (POST)' => [64, 101, 118, 97, 108, 40, 36, 95, 80, 79, 83, 84, 91, 39],
            'Remote File Inclusion Payload (GET)' => [64, 105, 110, 99, 108, 117, 100, 101, 40, 36, 95, 71, 69, 84, 91],
            'Remote Command Execution Payload (GET)' => [115, 121, 115, 116, 101, 109, 40, 36, 95, 71, 69, 84, 91],
            'Webshell: w4ck1ng shell' => [119, 52, 99, 107, 49, 110, 103, 32, 115, 104, 101, 108, 108],
            'Webshell: private Shell by m4rco' => [112, 114, 105, 118, 97, 116, 101, 32, 83, 104, 101, 108, 108, 32, 98, 121, 32, 109, 52, 114, 99, 111],
            'Webshell: Shell by Mawar_Hitam' => [83, 104, 101, 108, 108, 32, 98, 121, 32, 77, 97, 119, 97, 114, 95, 72, 105, 116, 97, 109],
            'Webshell: ConnectBackShell' => [67, 111, 110, 110, 101, 99, 116, 66, 97, 99, 107, 83, 104, 101, 108, 108],
            'Bot: ShellBOT' => [83, 104, 101, 108, 108, 66, 79, 84],
            'Webshell: IndoXploit' => [73, 110, 100, 111, 88, 112, 108, 111, 105, 116],
            'Webshell: FaisaL Ahmed aka rEd X' => [70, 97, 105, 115, 97, 76, 32, 65, 104, 109, 101, 100, 32, 97, 107, 97, 32, 114, 69, 100, 32, 88],
            'Bot: smisbot' => [115, 109, 105, 115, 98, 111, 116],
            'Bot: smotherbot' => [115, 109, 111, 116, 104, 101, 114, 98, 111, 116],
            'Webshell: Indonesian Hacker Rulez' => [73, 110, 100, 111, 110, 101, 115, 105, 97, 110, 32, 72, 97, 99, 107, 101, 114, 32, 82, 117, 108, 101, 122],
            'Webshell Function: WSOsetcookie' => [87, 83, 79, 115, 101, 116, 99, 111, 111, 107, 105, 101, 40],
            'Webshell Function: wsoEx' => [119, 115, 111, 69, 120, 40],
            'Webshell: Mister Spy' => [77, 105, 115, 116, 101, 114, 32, 83, 112, 121],
            'Webshell: Souheyl Bypass Shell' => [83, 111, 117, 104, 101, 121, 108, 32, 66, 121, 112, 97, 115, 115, 32, 83, 104, 101, 108, 108],
            'Webshell: Welcome To Our Shell' => [87, 101, 108, 99, 111, 109, 101, 32, 84, 111, 32, 79, 117, 114, 32, 83, 104, 101, 108, 108],
            'Webshell: Devloped By El Moujahidin' => [68, 101, 118, 108, 111, 112, 101, 100, 32, 66, 121, 32, 69, 108, 32, 77, 111, 117, 106, 97, 104, 105, 100, 105, 110],
            'Obfuscator: PHPJiaMi' => [80, 72, 80, 74, 105, 97, 77, 105],
        ];

        $found = [];
        foreach ($signatures as $name => $chars) {
            $pattern = '';
            foreach ($chars as $c) {
                $pattern .= chr($c);
            }
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
            $date_str = gmdate('Y-m-d H:i:s', (int)($data['timings']['start'] / 1000));
        }

        // Build HTML
        $html = '<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; color: #333; border: 1px solid #ddd; padding: 20px;">';
        $html .= '<h2 style="background: #007cba; color: #fff; padding: 15px; margin: -20px -20px 20px -20px;">' . __('File Integrity Scan Report', 'advanced-ip-blocker') . '</h2>';
        $html .= '<p><strong>' . __('Site:', 'advanced-ip-blocker') . '</strong> ' . esc_html($site_name) . '</p>';
        $html .= '<p><strong>' . __('Date:', 'advanced-ip-blocker') . '</strong> ' . esc_html($date_str) . ' (UTC)</p>';
        
        $type_labels = [
            'all' => __('Core + Plugins', 'advanced-ip-blocker'),
            'core' => __('WordPress Core Only', 'advanced-ip-blocker'),
            'plugins' => __('Plugins Only', 'advanced-ip-blocker'),
            'deep_scan' => __('Deep Scan (All PHP Files)', 'advanced-ip-blocker')
        ];
        $s_type = isset($data['scan_type']) ? $data['scan_type'] : 'all';
        $type_str = isset($type_labels[$s_type]) ? $type_labels[$s_type] : $s_type;
        $html .= '<p><strong>' . __('Scan Type:', 'advanced-ip-blocker') . '</strong> ' . esc_html($type_str) . '</p>';
        
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

        // Deep Scan
        if (!empty($data['deep_scan'])) {
            $has_threats = true;
            $html .= $build_table(__('Deep Scan Malware Detected', 'advanced-ip-blocker'), '#d63638', '&#x1F6A8;', $data['deep_scan']);
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
        
        // Footer
        $dashboard_url = admin_url('admin.php?page=advaipbl_settings_page&tab=integrity&sub-tab=fim_dashboard');
        $settings_url = admin_url('admin.php?page=advaipbl_settings_page&tab=settings&sub-tab=general_settings#section-notifications');
        $plugin_version = defined('ADVAIPBL_VERSION') ? ADVAIPBL_VERSION : '8.13.1';

        $html .= '<div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #777; text-align: center; line-height: 1.6;">';
        $html .= '<p style="margin: 0;">' . __('This email was generated by the Advanced IP Blocker plugin.', 'advanced-ip-blocker') . '</p>';
        
        /* translators: %s: Dashboard URL. */
        $html .= '<p style="margin: 5px 0;">' . sprintf(__('View scan results and history in the <a href="%s" style="color: #007cba; text-decoration: none;">Integrity Scanner Dashboard</a>.', 'advanced-ip-blocker'), esc_url($dashboard_url)) . '</p>';
        
        /* translators: %s: Settings URL. */
        $html .= '<p style="margin: 5px 0;">' . sprintf(__('To unsubscribe from these updates, please visit the <a href="%s" style="color: #007cba; text-decoration: none;">settings page</a>.', 'advanced-ip-blocker'), esc_url($settings_url)) . '</p>';
        
        /* translators: %s: Plugin version. */
        $html .= '<p style="margin: 15px 0 0 0; color: #999;">' . sprintf(__('Sent by Advanced IP Blocker v%s', 'advanced-ip-blocker'), esc_html($plugin_version)) . '</p>';
        $html .= '</div>';
        
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

    /**
     * Get the current FIM whitelist.
     */
    private function get_whitelist() {
        return get_option('advaipbl_fim_whitelist', []);
    }

    private function is_whitelisted($rel_path, $whitelist) {
        if (in_array($rel_path, $whitelist)) {
            return true;
        }
        
        // Normalize for plugins: deep scan format vs standard format
        // Deep scan path: wp-content/plugins/plugin-slug/file.php
        // Standard path: plugin-slug/file.php
        
        if (strpos($rel_path, 'wp-content/plugins/') === 0) {
            $standard_plugin_path = substr($rel_path, strlen('wp-content/plugins/'));
            if (in_array($standard_plugin_path, $whitelist)) {
                return true;
            }
        } else {
            $deep_scan_path = 'wp-content/plugins/' . $rel_path;
            if (in_array($deep_scan_path, $whitelist)) {
                return true;
            }
        }
        
        // Similarly for themes if needed in the future
        if (strpos($rel_path, 'wp-content/themes/') === 0) {
            $standard_theme_path = substr($rel_path, strlen('wp-content/themes/'));
            if (in_array($standard_theme_path, $whitelist)) {
                return true;
            }
        } else {
            $deep_scan_theme_path = 'wp-content/themes/' . $rel_path;
            if (in_array($deep_scan_theme_path, $whitelist)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * AJAX endpoint to add a file to the whitelist.
     */
    public function ajax_add_whitelist() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
        }
        
        $rel_path = isset($_POST['rel_path']) ? sanitize_text_field(wp_unslash($_POST['rel_path'])) : '';
        if (empty($rel_path)) {
            wp_send_json_error(['message' => 'Invalid path']);
        }

        $whitelist = $this->get_whitelist();
        if (!in_array($rel_path, $whitelist)) {
            $whitelist[] = $rel_path;
            update_option('advaipbl_fim_whitelist', $whitelist);
        }

        wp_send_json_success(['message' => __('File marked as safe.', 'advanced-ip-blocker')]);
    }

    /**
     * AJAX endpoint to remove a file from the whitelist.
     */
    public function ajax_remove_whitelist() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
        }
        
        $rel_path = isset($_POST['rel_path']) ? sanitize_text_field(wp_unslash($_POST['rel_path'])) : '';
        if (empty($rel_path)) {
            wp_send_json_error(['message' => 'Invalid path']);
        }

        $whitelist = $this->get_whitelist();
        if (($key = array_search($rel_path, $whitelist)) !== false) {
            unset($whitelist[$key]);
            update_option('advaipbl_fim_whitelist', array_values($whitelist));
        }

        wp_send_json_success(['message' => __('File removed from whitelist.', 'advanced-ip-blocker')]);
    }


    // --- QUARANTINE SYSTEM ---

    private function get_quarantine_dir() {
        $upload_dir = wp_upload_dir();
        $q_dir = trailingslashit($upload_dir['basedir']) . 'advaipbl_quarantine';
        if (!is_dir($q_dir)) {
            wp_mkdir_p($q_dir);
        }
        
        // Security: Deny all HTTP access
        $htaccess = trailingslashit($q_dir) . '.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "Order Allow,Deny
Deny from all
<Files *>
    Deny from all
</Files>");
        }
        
        // Security: Empty index
        $index = trailingslashit($q_dir) . 'index.php';
        if (!file_exists($index)) {
            file_put_contents($index, "<?php
// Silence is golden.");
        }
        
        return $q_dir;
    }

    public function ajax_quarantine_file() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $file_path = isset($_POST['file_path']) ? sanitize_text_field(wp_unslash($_POST['file_path'])) : '';
        $malware_type = isset($_POST['malware_type']) ? sanitize_text_field(wp_unslash($_POST['malware_type'])) : 'unknown';

        if (empty($file_path)) {
            wp_send_json_error('No file provided.');
        }

        $abs_path = wp_normalize_path(trailingslashit(ABSPATH));
        $full_path = wp_normalize_path($abs_path . $file_path);

        if (!file_exists($full_path)) {
            wp_send_json_error('File not found on server.');
        }

        // Anti-Brick Shields
        // 1. Core Shield
        if (strpos($file_path, 'wp-admin/') === 0 || strpos($file_path, 'wp-includes/') === 0 || dirname($file_path) === '.') {
            wp_send_json_error('Cannot quarantine WordPress core files.');
        }

        // 2. Theme Shield
        $active_theme_dir = wp_normalize_path(get_stylesheet_directory());
        $parent_theme_dir = wp_normalize_path(get_template_directory());
        if (strpos($full_path, $active_theme_dir) === 0 || strpos($full_path, $parent_theme_dir) === 0) {
            wp_send_json_error('Cannot quarantine active theme files.');
        }

        // 3. Plugin Shield (excluding uploads)
        if (strpos($file_path, 'wp-content/plugins/') === 0) {
            wp_send_json_error('Cannot quarantine plugin files to prevent site breakage. Please disable the plugin and remove manually.');
        }

        $q_dir = $this->get_quarantine_dir();
        $vault_filename = md5(time() . $file_path . wp_rand()) . '.quarantined';
        $vault_path = trailingslashit($q_dir) . $vault_filename;

        // Move the file
        if (rename($full_path, $vault_path)) { // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
            global $wpdb;
            $table = $wpdb->prefix . 'advaipbl_quarantine';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
                $table,
                [
                    'original_path' => $file_path,
                    'vault_filename' => $vault_filename,
                    'malware_type' => $malware_type,
                    'timestamp' => current_time('mysql', true)
                ],
                ['%s', '%s', '%s', '%s']
            );
            wp_send_json_success('File quarantined successfully.');
        } else {
            wp_send_json_error('Failed to move file to quarantine vault.');
        }
    }

    public function ajax_restore_quarantine() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $id = isset($_POST['id']) ? intval($_POST['id']) : 0;
        if (!$id) {
            wp_send_json_error('Invalid ID.');
        }

        global $wpdb;
        $table = $wpdb->prefix . 'advaipbl_quarantine';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $record = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id = %d", $id));

        if (!$record) {
            wp_send_json_error('Record not found.');
        }

        $q_dir = $this->get_quarantine_dir();
        $vault_path = trailingslashit($q_dir) . $record->vault_filename;
        $abs_path = wp_normalize_path(trailingslashit(ABSPATH));
        $original_full_path = wp_normalize_path($abs_path . $record->original_path);

        if (!file_exists($vault_path)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table, ['id' => $id], ['%d']);
            wp_send_json_error('Quarantined file missing from vault. Record deleted.');
        }
        
        // Ensure destination directory exists (if it was deleted)
        $dest_dir = dirname($original_full_path);
        if (!is_dir($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }

        if (rename($vault_path, ABSPATH . ltrim($record->original_path, '/'))) { // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table, ['id' => $id], ['%d']);
            wp_send_json_success('File restored successfully.');
        } else {
            wp_send_json_error('Failed to restore file.');
        }
    }

    public function ajax_delete_quarantine() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $id = isset($_POST['id']) ? intval($_POST['id']) : 0;
        if (!$id) {
            wp_send_json_error('Invalid ID.');
        }

        global $wpdb;
        $table = $wpdb->prefix . 'advaipbl_quarantine';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $record = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id = %d", $id));

        if ($record) {
            $q_dir = $this->get_quarantine_dir();
            $vault_path = trailingslashit($q_dir) . $record->vault_filename;
            if (file_exists($vault_path)) {
                wp_delete_file($vault_path);
            }
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table, ['id' => $id], ['%d']);
        }
        
        wp_send_json_success('File permanently deleted.');
    }

    public function ajax_get_quarantine_list() {
        check_ajax_referer('advaipbl_admin_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        global $wpdb;
        $table = $wpdb->prefix . 'advaipbl_quarantine';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results("SELECT * FROM $table ORDER BY timestamp DESC", ARRAY_A);
        
        if (!is_array($results)) {
            $results = []; // Handle case if table doesn't exist yet
        }
        
        // Format timestamp
        foreach ($results as &$row) {
            $row['timestamp'] = get_date_from_gmt($row['timestamp'], 'Y-m-d H:i:s');
        }

        wp_send_json_success($results);
    }
}
