<?php
if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Remote_Notices {

    private $api_url = 'https://advaipbl.com/wp-json/aib-api/v3/notifications';
    
    public function __construct() {
        add_action('admin_notices', [$this, 'display_notices']);
        add_action('wp_ajax_advaipbl_dismiss_notice', [$this, 'ajax_dismiss_notice']);
        add_action('advaipbl_daily_notices_sync', [$this, 'fetch_remote_notices']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
        
        // Register cron if not exists
        if (!wp_next_scheduled('advaipbl_daily_notices_sync')) {
            wp_schedule_event(time(), 'daily', 'advaipbl_daily_notices_sync');
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

        $current_version = defined('ADVAIPBL_VERSION') ? ADVAIPBL_VERSION : '8.13.9';

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
