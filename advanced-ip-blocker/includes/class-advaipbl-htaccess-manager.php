<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Htaccess_Manager
{
    private $plugin;

    private $marker = 'Advanced IP Blocker';

    public function __construct(ADVAIPBL_Main $plugin_instance)
    {
        $this->plugin = $plugin_instance;
    }

    /**
     * Gets the full path to the .htaccess file.
     *
     * @return string
     */
    public function get_htaccess_path()
    {
        if (! function_exists('get_home_path')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        return get_home_path() . '.htaccess';
    }

    /**
     * Verifies if the .htaccess file exists and is writable.
     * Uses wp_is_writable() to comply with WP standards.
     *
     * @return bool
     */
    public function is_writable()
    {
        $path = $this->get_htaccess_path();

        return (file_exists($path) && wp_is_writable($path)) || (! file_exists($path) && wp_is_writable(dirname($path)));
    }

    /**
     * Creates a backup of the current .htaccess file in a secure folder.
     * Keeps only the last 30 backups.
     *
     * @return bool|string Backup path if successful, false on failure.
     */
    public function create_backup()
    {
        $htaccess_path = $this->get_htaccess_path();
        if (! file_exists($htaccess_path)) {
            return false;
        }

        $upload_dir = wp_upload_dir();
        $backup_dir = $upload_dir['basedir'] . '/advaipbl-backups';

        if (! file_exists($backup_dir)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
            if (! wp_mkdir_p($backup_dir)) {
                $this->plugin->log_event('Backup failed: Could not create directory ' . $backup_dir, 'error');

                return false;
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents($backup_dir . '/.htaccess', 'deny from all');
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents($backup_dir . '/index.php', '<?php // Silence is golden');
        }

        if (! wp_is_writable($backup_dir)) {
            $this->plugin->log_event('Backup failed: Directory ' . $backup_dir . ' is not writable.', 'error');

            return false;
        }

        $backup_filename = 'htaccess_backup_' . gmdate('Y-m-d_H-i-s') . '_' . bin2hex(random_bytes(8)) . '.txt';
        $backup_path = $backup_dir . '/' . $backup_filename;

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_copy
        if (copy($htaccess_path, $backup_path)) {
            $files = glob($backup_dir . '/htaccess_backup_*.txt');

            if ($files && count($files) > 30) {
                array_multisort(array_map('filemtime', $files), SORT_NUMERIC, SORT_ASC, $files);
                $to_delete = array_slice($files, 0, count($files) - 30);
                foreach ($to_delete as $file) {
                    wp_delete_file($file);
                }
            }

            return $backup_path;
        } else {
            $this->plugin->log_event('Backup failed: Could not copy .htaccess to ' . $backup_path, 'error');
        }

        return false;
    }

    /**
     * Gets IPs to block.
     * Excludes hyphenated ranges (-) since Apache doesn't natively support them in Require ip.
     */
    private function get_ips_to_block()
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';

        $include_all = !empty($this->plugin->options['enable_htaccess_all_ips']);

        $sql = "SELECT ip_range FROM {$table_name} WHERE ip_range NOT LIKE '%-%'";

        if (! $include_all) {
            $sql .= " AND (block_type IN ('manual', 'bulk_import') OR expires_at = 0)";
        }

        $limit = $include_all ? 2000 : 1000;

        $sql .= " ORDER BY id DESC LIMIT %d";

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $wpdb->get_col($wpdb->prepare($sql, $limit));

        return $results ? $results : [];
    }

    public function generate_rules_content()
    {
        $rules = [];
        $options = $this->plugin->options;

        $hardening_files = [];
        if (! empty($options['htaccess_protect_system_files'])) {
            $hardening_files[] = '\.(7z|bak|bz2|com|conf|dist|fla|git|env|inc|ini|log|old|psd|rar|tar|tgz|save|sh|sql|svn|swo|swp)$';
            $hardening_files[] = '^\.ds_store$';
        }
        if (! empty($options['htaccess_protect_wp_config'])) {
            $hardening_files[] = '^wp-config(-sample)?\.php$';
        }
        if (! empty($options['htaccess_protect_readme'])) {
            $hardening_files[] = '^(readme\.(html|txt)|license\.txt)$';
        }

        if (! empty($hardening_files)) {
            $regex = '(?i)(' . implode('|', $hardening_files) . ')';

            $rules[] = '<FilesMatch "' . $regex . '">';
            $rules[] = '    <IfModule mod_authz_core.c>';
            $rules[] = '        Require all denied';
            $rules[] = '    </IfModule>';
            $rules[] = '    <IfModule !mod_authz_core.c>';
            $rules[] = '        Order allow,deny';
            $rules[] = '        Deny from all';
            $rules[] = '    </IfModule>';
            $rules[] = '</FilesMatch>';
            $rules[] = '';
        }

        $ips_to_block = [];
        if (! empty($options['enable_htaccess_ip_blocking'])) {
            $ips_to_block = $this->get_ips_to_block();
        }

        if (! empty($ips_to_block)) {
            $rules[] = '# IP Blocking Rules';

            $setenvif_rules = [];
            foreach ($ips_to_block as $ip) {
                if (strpos($ip, '/') === false) {
                    $ip_regex = str_replace('.', '\.', $ip);
                    $ip_regex = '^' . $ip_regex . '$';

                    $setenvif_rules[] = '    SetEnvIF REMOTE_ADDR "' . $ip_regex . '" DenyAccess';
                    $setenvif_rules[] = '    SetEnvIF X-FORWARDED-FOR "' . $ip_regex . '" DenyAccess';
                    $setenvif_rules[] = '    SetEnvIF X-CLUSTER-CLIENT-IP "' . $ip_regex . '" DenyAccess';
                }
            }

            if (!empty($setenvif_rules)) {
                $rules[] = '<IfModule mod_setenvif.c>';
                $rules = array_merge($rules, $setenvif_rules);
                $rules[] = '</IfModule>';
            }

            $rules[] = '';

            $rules[] = '<IfModule mod_authz_core.c>';
            $rules[] = '    <RequireAll>';
            $rules[] = '        Require all granted';
            $rules[] = '        Require not env DenyAccess';
            foreach ($ips_to_block as $ip) {
                if (empty(trim($ip))) {
                    continue;
                }
                $rules[] = '        Require not ip ' . $ip;
            }
            $rules[] = '    </RequireAll>';
            $rules[] = '</IfModule>';

            $rules[] = '<IfModule !mod_authz_core.c>';
            $rules[] = '    Order allow,deny';
            $rules[] = '    Allow from all';
            $rules[] = '    Deny from env=DenyAccess';
            foreach ($ips_to_block as $ip) {
                $rules[] = '    Deny from ' . $ip;
            }
            $rules[] = '</IfModule>';
        }

        // 3. Security Headers
        $security_headers = get_option('advaipbl_security_headers');
        if (is_array($security_headers)) {
            $header_rules = [];
            foreach ($security_headers as $key => $header) {
                if (!empty($header['enabled']) && !empty($header['name']) && !empty($header['value'])) {
                    $safe_value = str_replace('"', '\"', trim($header['value']));
                    if ($key === 'hsts') {
                        $header_rules[] = '    Header set ' . trim($header['name']) . ' "' . $safe_value . '" env=HTTPS';
                    } else {
                        $header_rules[] = '    Header set ' . trim($header['name']) . ' "' . $safe_value . '"';
                    }
                }
            }
            if (!empty($header_rules)) {
                $rules[] = '';
                $rules[] = '# Security Headers';
                $rules[] = '<IfModule mod_headers.c>';
                $rules = array_merge($rules, $header_rules);
                $rules[] = '</IfModule>';
            }
        }

        if (empty($rules)) {
            return "# No active rules selected in Advanced IP Blocker settings.";
        }

        return implode("\n", $rules);
    }

    public function update_htaccess()
    {
        if (! $this->is_writable()) {
            return new WP_Error('file_not_writable', 'The .htaccess file is not writable.');
        }

        $this->create_backup();

        $rules_string = $this->generate_rules_content();
        $rules_array = explode("\n", $rules_string);

        if (! function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        $result = insert_with_markers($this->get_htaccess_path(), $this->marker, $rules_array);

        if (! $result) {
            return new WP_Error('write_failed', 'Failed to write to .htaccess file.');
        }

        if (isset($this->plugin->file_verifier) && ! empty($this->plugin->options['enable_fim'])) {
            $this->plugin->file_verifier->update_file_hash($this->get_htaccess_path());
        }

        return true;
    }

    public function remove_rules()
    {
        if (! function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        return insert_with_markers($this->get_htaccess_path(), $this->marker, []);
    }
}
