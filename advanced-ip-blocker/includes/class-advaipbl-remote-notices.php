<?php
if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Remote_Notices {

    private $api_url = 'https://advaipbl.com/wp-json/aib-api/v3/notifications?v=' . ADVAIPBL_VERSION;
    
    public function __construct() {
        add_action('admin_notices', [$this, 'display_notices']);
        add_action('wp_ajax_advaipbl_dismiss_notice', [$this, 'ajax_dismiss_notice']);
        add_action('advaipbl_fetch_notices_event', [$this, 'fetch_remote_notices']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
        
        // Clear old daily cron hook
        if (wp_next_scheduled('advaipbl_daily_notices_sync')) {
            wp_clear_scheduled_hook('advaipbl_daily_notices_sync');
        }

        // Register new 6-hour cron if not exists
        if (!wp_next_scheduled('advaipbl_fetch_notices_event')) {
            wp_schedule_event(time(), 'advaipbl_6_hours', 'advaipbl_fetch_notices_event');
        }
    }

    public function fetch_remote_notices() {
        $response = wp_remote_get($this->api_url, [
            'timeout' => 15,
            'sslverify' => false // For local dev/flexibility, though true is better for prod
        ]);

        if (is_wp_error($response)) {
            return;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code === 200) {
            $body = wp_remote_retrieve_body($response);
            $notices = json_decode($body, true);
            if (is_array($notices)) {
                update_option('advaipbl_remote_notices', $notices, false); // false = not autoloaded unless needed
            }
        }
    }

    public function display_notices() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $notices = get_option('advaipbl_remote_notices', []);
        $dismissed = get_option('advaipbl_dismissed_notices', []);
        
        if (empty($notices) || !is_array($notices)) {
            return;
        }

        $current_version = defined('ADVAIPBL_VERSION') ? ADVAIPBL_VERSION : '8.13.21';

        foreach ($notices as $notice) {
            if (in_array($notice['id'], $dismissed)) {
                continue;
            }

            // Version check
            if (!empty($notice['target_version_min']) && version_compare($current_version, $notice['target_version_min'], '<')) {
                continue;
            }
            if (!empty($notice['target_version_max']) && version_compare($current_version, $notice['target_version_max'], '>')) {
                continue;
            }

            if (!$this->matches_environment_filters($notice)) {
                continue;
            }

            $type = isset($notice['type']) ? sanitize_text_field($notice['type']) : 'info';
            // Classes: notice-info, notice-success, notice-warning, notice-error
            $class = 'notice notice-' . $type . ' is-dismissible advaipbl-remote-notice';
            
            $button_html = '';
            if (!empty($notice['button_text']) && !empty($notice['button_link'])) {
                $button_html = '<p><a href="' . esc_url($notice['button_link']) . '" class="button button-primary">' . esc_html($notice['button_text']) . '</a></p>';
            }

            echo '<div class="' . esc_attr($class) . '" data-notice-id="' . esc_attr($notice['id']) . '">';
            echo '<p>' . wp_kses_post($notice['message']) . '</p>';
            echo wp_kses_post($button_html);
            echo '</div>';
        }
    }

    private function matches_environment_filters($notice) {
        // 1. PHP branch version check (e.g. "8.2.35, 8.3.36, 8.4.27, 8.5.12")
        if (!empty($notice['target_php_safe'])) {
            $current_php = preg_replace('/[^0-9\.].*$/', '', PHP_VERSION);
            $parts = explode('.', $current_php);
            $current_branch = isset($parts[0], $parts[1]) ? $parts[0] . '.' . $parts[1] : $current_php;

            $safe_versions = array_filter(array_map('trim', explode(',', $notice['target_php_safe'])));
            $safe_branches = [];
            $lowest_branch = null;

            foreach ($safe_versions as $sv) {
                $sv_clean = preg_replace('/[^0-9\.]/', '', $sv);
                if (empty($sv_clean)) {
                    continue;
                }
                $sv_parts = explode('.', $sv_clean);
                if (count($sv_parts) >= 2) {
                    $branch = $sv_parts[0] . '.' . $sv_parts[1];
                    $safe_branches[$branch] = $sv_clean;
                    if ($lowest_branch === null || version_compare($branch, $lowest_branch, '<')) {
                        $lowest_branch = $branch;
                    }
                }
            }

            if (!empty($safe_branches)) {
                $is_php_vulnerable = false;
                if (isset($safe_branches[$current_branch])) {
                    if (version_compare($current_php, $safe_branches[$current_branch], '<')) {
                        $is_php_vulnerable = true;
                    }
                } elseif ($lowest_branch !== null && version_compare($current_branch, $lowest_branch, '<')) {
                    // Older EOL branch below the minimum supported branch
                    $is_php_vulnerable = true;
                }

                if (!$is_php_vulnerable) {
                    return false;
                }
            }
        }

        // 2. Installed Plugin / Theme check (e.g. "duplicator:1.5.17, duplicator-pro:4.6.10")
        $item_type = isset($notice['target_item_type']) ? $notice['target_item_type'] : 'none';
        $item_rules_raw = isset($notice['target_item_rules']) ? trim($notice['target_item_rules']) : '';
        $item_status = isset($notice['target_item_status']) ? $notice['target_item_status'] : 'installed';

        if (($item_type === 'plugin' || $item_type === 'theme') && !empty($item_rules_raw)) {
            $rules = array_filter(array_map('trim', explode(',', $item_rules_raw)));
            $matched_item = false;

            foreach ($rules as $rule) {
                if (!preg_match('/^([a-zA-Z0-9_\-]+)\s*(?:(<=|<|=|:)\s*([0-9a-zA-Z\.\-_]+))?$/', $rule, $matches)) {
                    continue;
                }
                $target_slug = strtolower($matches[1]);
                $operator = !empty($matches[2]) ? ($matches[2] === ':' ? '<=' : $matches[2]) : '';
                $target_ver = isset($matches[3]) ? $matches[3] : '';

                if ($item_type === 'plugin') {
                    if (!function_exists('get_plugins')) {
                        require_once ABSPATH . 'wp-admin/includes/plugin.php';
                    }
                    $all_plugins = get_plugins();
                    foreach ($all_plugins as $plugin_file => $plugin_data) {
                        $dir_slug = strpos($plugin_file, '/') !== false ? dirname($plugin_file) : basename($plugin_file, '.php');
                        if (strtolower($dir_slug) !== $target_slug) {
                            continue;
                        }
                        if ($item_status === 'active' && !is_plugin_active($plugin_file) && (!function_exists('is_plugin_active_for_network') || !is_plugin_active_for_network($plugin_file))) {
                            continue;
                        }
                        $installed_ver = isset($plugin_data['Version']) ? $plugin_data['Version'] : '';
                        if (empty($operator) || empty($target_ver) || (!empty($installed_ver) && version_compare($installed_ver, $target_ver, $operator))) {
                            $matched_item = true;
                            break 2;
                        }
                    }
                } elseif ($item_type === 'theme') {
                    $theme = wp_get_theme($target_slug);
                    if ($theme->exists()) {
                        if ($item_status === 'active') {
                            $active_theme = wp_get_theme();
                            $active_slug = strtolower($active_theme->get_stylesheet());
                            $parent_slug = strtolower($active_theme->get_template());
                            if ($active_slug !== $target_slug && $parent_slug !== $target_slug) {
                                continue;
                            }
                        }
                        $installed_ver = $theme->get('Version');
                        if (empty($operator) || empty($target_ver) || (!empty($installed_ver) && version_compare($installed_ver, $target_ver, $operator))) {
                            $matched_item = true;
                            break;
                        }
                    }
                }
            }

            if (!$matched_item) {
                return false;
            }
        }

        return true;
    }

    public function ajax_dismiss_notice() {
        check_ajax_referer('advaipbl_dismiss_notice_nonce', 'security');

        if (!current_user_can('manage_options')) {
            wp_die(-1);
        }

        $notice_id = isset($_POST['notice_id']) ? sanitize_text_field(wp_unslash($_POST['notice_id'])) : '';
        if ($notice_id) {
            $dismissed = get_option('advaipbl_dismissed_notices', []);
            if (!in_array($notice_id, $dismissed)) {
                $dismissed[] = $notice_id;
                update_option('advaipbl_dismissed_notices', $dismissed, false);
            }
        }

        wp_send_json_success();
    }

    public function enqueue_scripts($hook) {
        // Enqueue small inline JS for the dismiss action
        $version = defined('ADVAIPBL_VERSION') ? ADVAIPBL_VERSION : '1.0.0';
        wp_register_script('advaipbl-remote-notices-js', false, [], $version, true);
        wp_enqueue_script('advaipbl-remote-notices-js');
        
        $nonce = wp_create_nonce('advaipbl_dismiss_notice_nonce');
        
        $js = "
        jQuery(document).ready(function($) {
            $(document).on('click', '.advaipbl-remote-notice .notice-dismiss', function() {
                var notice_id = $(this).parent('.advaipbl-remote-notice').data('notice-id');
                if (notice_id) {
                    $.post(ajaxurl, {
                        action: 'advaipbl_dismiss_notice',
                        security: '{$nonce}',
                        notice_id: notice_id
                    });
                }
            });
        });
        ";
        wp_add_inline_script('advaipbl-remote-notices-js', $js);
    }
}
