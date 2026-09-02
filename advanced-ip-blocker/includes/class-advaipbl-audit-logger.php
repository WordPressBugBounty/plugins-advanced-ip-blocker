<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Audit_Logger
{
    private $main_instance;

    private $table_name;

    public function __construct($main_instance)
    {
        $this->main_instance = $main_instance;
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'advaipbl_activity_log';

        $this->init_hooks();
    }

    private function init_hooks()
    {
        add_action('wp_login', [$this, 'log_login'], 10, 2);
        add_action('wp_login_failed', [$this, 'log_login_failed']);

        add_action('activated_plugin', [$this, 'log_plugin_activation'], 10, 2);
        add_action('deactivated_plugin', [$this, 'log_plugin_deactivation'], 10, 2);

        add_action('user_register', [$this, 'log_user_registration']);
        add_action('deleted_user', [$this, 'log_user_deletion'], 10, 3);

        add_action('update_option_' . ADVAIPBL_Main::OPTION_SETTINGS, [$this, 'log_settings_change'], 10, 3);

        add_action('advaipbl_purge_old_logs_event', [$this, 'cleanup_logs']);

        // Profile & Privilege Escalation
        add_action('profile_update', [$this, 'log_profile_update'], 10, 2);
        add_action('set_user_role', [$this, 'log_role_change'], 10, 3);

        // Core, Theme, Plugin Updates
        add_action('upgrader_process_complete', [$this, 'log_upgrader_process'], 10, 2);

        // Critical Options Updates
        add_action('updated_option', [$this, 'log_critical_option_update'], 10, 3);

        // Theme Switching
        add_action('switch_theme', [$this, 'log_theme_switch'], 10, 3);
    }

    /**
     * Records an activity in the audit log.
     *
     * @param string $type The event type key.
     * @param string $severity 'info', 'warning', 'critical'.
     * @param array $details Contextual data.
     * @param int|null $user_id Optional user ID.
     */
    public function log_activity($type, $severity, $details = [], $user_id = null)
    {
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

    public function log_login($user_login, $user)
    {
        $this->log_activity('user_login', 'info', ['username' => $user_login], $user->ID);
    }

    public function log_login_failed($username)
    {
        $this->log_activity('login_failed', 'warning', ['username' => $username, 'error' => 'Invalid credentials'], 0);
    }

    public function log_plugin_activation($plugin, $network_wide)
    {
        $this->log_activity('plugin_activated', 'info', ['plugin' => $plugin, 'network_wide' => $network_wide]);
    }

    public function log_plugin_deactivation($plugin, $network_wide)
    {
        $this->log_activity('plugin_deactivated', 'warning', ['plugin' => $plugin, 'network_wide' => $network_wide]);
    }

    public function log_user_registration($user_id)
    {
        $user = get_userdata($user_id);
        $this->log_activity('user_created', 'info', ['username' => $user->user_login, 'role' => implode(', ', $user->roles)]);
    }

    public function log_user_deletion($id, $reassign, $user)
    {
        $this->log_activity('user_deleted', 'warning', ['username' => $user->user_login, 'reassigned_to' => $reassign]);
    }

    public function log_settings_change($old_value, $value, $option)
    {
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

    public function log_profile_update($user_id, $old_user_data)
    {
        $user = get_userdata($user_id);
        $changes = [];
        if ($user->user_email !== $old_user_data->user_email) {
            $changes['email'] = ['old' => $old_user_data->user_email, 'new' => $user->user_email];
        }
        if ($user->user_pass !== $old_user_data->user_pass) {
            $changes['password'] = 'changed';
        }
        
        if (!empty($changes)) {
            $this->log_activity('profile_updated', 'warning', [
                'username' => $user->user_login,
                'changes'  => $changes
            ], get_current_user_id());
        }
    }

    public function log_role_change($user_id, $role, $old_roles)
    {
        $user = get_userdata($user_id);
        $this->log_activity('role_changed', 'critical', [
            'username' => $user->user_login,
            'new_role' => $role,
            'old_roles' => is_array($old_roles) ? implode(', ', $old_roles) : ''
        ], get_current_user_id());
    }

    public function log_upgrader_process($upgrader_object, $options)
    {
        if (isset($options['action']) && isset($options['type'])) {
            $this->log_activity('system_updated', 'info', [
                'action' => $options['action'],
                'type'   => $options['type']
            ], get_current_user_id());
        }
    }

    public function log_critical_option_update($option, $old_value, $value)
    {
        $critical_options = ['siteurl', 'home', 'users_can_register', 'default_role', 'admin_email'];
        if (in_array($option, $critical_options, true)) {
            $this->log_activity('critical_setting_changed', 'critical', [
                'option'    => $option,
                'old_value' => is_scalar($old_value) ? $old_value : 'complex_data',
                'new_value' => is_scalar($value) ? $value : 'complex_data'
            ], get_current_user_id());
        }
    }

    public function log_theme_switch($new_name, $new_theme, $old_theme)
    {
        $old_theme_name = is_object($old_theme) ? $old_theme->get('Name') : (string) $old_theme;
        $this->log_activity('theme_switched', 'warning', [
            'new_theme' => $new_name,
            'old_theme' => $old_theme_name
        ], get_current_user_id());
    }

    /**
     * Retrieves logs with pagination.
     */
    public function get_logs($limit = 20, $offset = 0)
    {
        global $wpdb;

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->table_name} ORDER BY timestamp DESC LIMIT %d OFFSET %d",
            $limit,
            $offset
        ), ARRAY_A);
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    /**
     * Cleans up logs older than the retention period.
     */
    /**
     * Cleans up logs older than the retention period.
     */
    public function cleanup_logs()
    {
        $retention_days = isset($this->main_instance->options['log_retention_days']) ? (int)$this->main_instance->options['log_retention_days'] : 30;

        if ($retention_days <= 0) {
            return;
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
    public function clear_all_logs()
    {
        global $wpdb;

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $wpdb->query("TRUNCATE TABLE {$this->table_name}");
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }
}
