<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Audit_Logger {

    private $main_instance;
    private $table_name;

    public function __construct($main_instance) {
        $this->main_instance = $main_instance;
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'advaipbl_activity_log';
        
        $this->init_hooks();
    }

    private function init_hooks() {
        // Auth Events
        add_action('wp_login', [$this, 'log_login'], 10, 2);
        add_action('wp_login_failed', [$this, 'log_login_failed']);
        
        // Plugin Events
        add_action('activated_plugin', [$this, 'log_plugin_activation'], 10, 2);
        add_action('deactivated_plugin', [$this, 'log_plugin_deactivation'], 10, 2);
        
        // User Events
        add_action('user_register', [$this, 'log_user_registration']);
        add_action('deleted_user', [$this, 'log_user_deletion'], 10, 3);
        
        // Plugin Settings Change
        add_action('update_option_' . ADVAIPBL_Main::OPTION_SETTINGS, [$this, 'log_settings_change'], 10, 3);
        
        // Cron
        add_action('advaipbl_daily_event', [$this, 'cleanup_logs']);
    }

    /**
     * Records an activity in the audit log.
     *
     * @param string $type The event type key.
     * @param string $severity 'info', 'warning', 'critical'.
     * @param array $details Contextual data.
     * @param int|null $user_id Optional user ID.
     */
    public function log_activity($type, $severity, $details = [], $user_id = null) {
        // Check if feature is enabled
        if (empty($this->main_instance->options['enable_audit_log'])) {
            return;
        }

        global $wpdb;
        
        if (!$user_id) {
            $user_id = get_current_user_id();
        }

        $ip = $this->main_instance->get_client_ip();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->insert(
            $this->table_name,
            [
                'user_id'    => $user_id,
                'event_type' => sanitize_key($type),
                'severity'   => sanitize_key($severity),
                'details'    => wp_json_encode($details),
                'ip_address' => $ip,
                'timestamp'  => current_time('mysql'),
            ]
        );
    }

    // --- Hook Callbacks ---

    public function log_login($user_login, $user) {
        $this->log_activity('user_login', 'info', ['username' => $user_login], $user->ID);
    }

    public function log_login_failed($username) {
        // For failed logins, we don't have a user ID, so passing 0 or null.
        $this->log_activity('login_failed', 'warning', ['username' => $username, 'error' => 'Invalid credentials'], 0);
    }

    public function log_plugin_activation($plugin, $network_wide) {
        $this->log_activity('plugin_activated', 'info', ['plugin' => $plugin, 'network_wide' => $network_wide]);
    }

    public function log_plugin_deactivation($plugin, $network_wide) {
        $this->log_activity('plugin_deactivated', 'warning', ['plugin' => $plugin, 'network_wide' => $network_wide]);
    }

    public function log_user_registration($user_id) {
        $user = get_userdata($user_id);
        $this->log_activity('user_created', 'info', ['username' => $user->user_login, 'role' => implode(', ', $user->roles)]);
    }

    public function log_user_deletion($id, $reassign, $user) {
        $this->log_activity('user_deleted', 'warning', ['username' => $user->user_login, 'reassigned_to' => $reassign]);
    }

    public function log_settings_change($old_value, $value, $option) {
        // Calculate raw diff to avoid storing sensitive info if possible, 
        // but for now we just log that settings changed.
        // We avoid logging the full dump to save space and privacy.
        $changed_keys = [];
        if (is_array($old_value) && is_array($value)) {
            foreach ($value as $k => $v) {
                if (!isset($old_value[$k]) || $old_value[$k] !== $v) {
                    $changed_keys[] = $k;
                }
            }
        }
        
        if (!empty($changed_keys)) {
             $this->log_activity('settings_updated', 'warning', ['changed_fields' => $changed_keys]);
        }
    }
    
    /**
     * Retrieves logs with pagination.
     */
    public function get_logs($limit = 20, $offset = 0) {
        global $wpdb;
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->table_name} ORDER BY timestamp DESC LIMIT %d OFFSET %d",
            $limit, $offset
        ), ARRAY_A);
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }
    
    /**
     * Cleans up logs older than the retention period.
     */
    /**
     * Cleans up logs older than the retention period.
     */
    public function cleanup_logs() {
        $retention_days = isset($this->main_instance->options['log_retention_days']) ? (int)$this->main_instance->options['log_retention_days'] : 30;
        
        if ($retention_days <= 0) {
            return; // 0 means keep forever (or disabled cleanup)
        }
        
        global $wpdb;
        // Use gmdate to avoid timezone warnings and ensure consistency
        $cutoff_date = gmdate('Y-m-d H:i:s', current_time('timestamp') - ($retention_days * DAY_IN_SECONDS));
        
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($wpdb->prepare("DELETE FROM {$this->table_name} WHERE timestamp < %s", $cutoff_date));
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    /**
     * Clears all activity logs.
     * 
     * @return int|false Number of rows deleted or false on error.
     */
    public function clear_all_logs() {
        global $wpdb;
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $wpdb->query("TRUNCATE TABLE {$this->table_name}");
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }
}
