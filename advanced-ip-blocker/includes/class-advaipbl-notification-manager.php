<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class ADVAIPBL_Notification_Manager
 * 
 * Handles all notification logic (Email and Push/Webhooks).
 */
class ADVAIPBL_Notification_Manager {

    /**
     * @var ADVAIPBL_Main
     */
    private $plugin;

    public function __construct(ADVAIPBL_Main $plugin) {
        $this->plugin = $plugin;
        
        // Hooks for Cron Jobs
        add_action('advaipbl_send_summary_email', [$this, 'send_summary_email']);
        add_action('advaipbl_send_signature_summary_email', [$this, 'send_signature_summary_email']);
        add_action('advaipbl_abuseipdb_limit_email', [$this, 'send_abuseipdb_limit_email']);
    }

    /**
     * Processes and sends the daily/weekly security summary email.
     */
    /**
     * Processes and sends the daily/weekly security summary email (Standard Blocks).
     */
    public function send_summary_email() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_notifications_queue';
        
        // Fetch only standard notifications
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $notifications = $wpdb->get_results("SELECT * FROM $table_name WHERE block_type != 'signature' ORDER BY timestamp ASC");
        
        if (empty($notifications)) {
            return;
        }

        $options = $this->plugin->options;
        $to = !empty($options['notification_email']) && is_email($options['notification_email']) ? $options['notification_email'] : get_option('admin_email');
        
        $this->send_grouped_summary_email($notifications, $to, 'standard');

        // Clear ONLY processed notifications
        $ids = array_map(function($n) { return (int) $n->id; }, $notifications);
        if (!empty($ids)) {
            $ids_placeholder = implode(',', $ids);
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query("DELETE FROM $table_name WHERE id IN ($ids_placeholder)");
        }
    }

    /**
     * Processes and sends the daily/weekly security summary email (Signatures).
     */
    public function send_signature_summary_email() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_notifications_queue';
        
        // Fetch only signature notifications
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $notifications = $wpdb->get_results("SELECT * FROM $table_name WHERE block_type = 'signature' ORDER BY timestamp ASC");
        
        if (empty($notifications)) {
            return;
        }

        $options = $this->plugin->options;
        
        // Determine Recipient
        $recipient_type = $options['signature_notification_recipient'] ?? 'default';
        $to = get_option('admin_email');
        
        if ($recipient_type === 'default') {
            $to = !empty($options['notification_email']) ? $options['notification_email'] : get_option('admin_email');
        } elseif ($recipient_type === 'custom') {
            $to = !empty($options['signature_notification_custom_email']) ? $options['signature_notification_custom_email'] : get_option('admin_email');
        }

        if (!is_email($to)) {
            $to = get_option('admin_email');
        }

        $this->send_grouped_summary_email($notifications, $to, 'signature');

        // Clear ONLY processed notifications
        $ids = array_map(function($n) { return (int) $n->id; }, $notifications);
        if (!empty($ids)) {
            $ids_placeholder = implode(',', $ids);
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query("DELETE FROM $table_name WHERE id IN ($ids_placeholder)");
        }
    }

    /**
     * Helper to send a grouped summary email.
     */
    private function send_grouped_summary_email($notifications, $to, $type) {
        $site_name = get_bloginfo('name');
        $total_blocks = count($notifications);
        
        if ($type === 'signature') {
            /* translators: 1: Site name, 2: Total number. */
            $email_subject = sprintf(__('[%1$s] Security Digest: %2$d Attack Signatures', 'advanced-ip-blocker'), $site_name, $total_blocks);
            /* translators: %d: Total number of signatures. */
            $template_title = sprintf(__('Attack Signature Digest (%d)', 'advanced-ip-blocker'), $total_blocks);
            $intro_text = esc_html__('Here is the summary of attack signatures detected and blocked in the last period.', 'advanced-ip-blocker');
        } else {
            /* translators: 1: Site name, 2: Total number. */
            $email_subject = sprintf(__('[%1$s] Security Summary: %2$d New Blocks', 'advanced-ip-blocker'), $site_name, $total_blocks);
            /* translators: %d: Total number. */
            $template_title = sprintf(_n('%d New Block', '%d New Blocks', $total_blocks, 'advanced-ip-blocker'), $total_blocks);
            $intro_text = esc_html__('Here is your security summary for the last period.', 'advanced-ip-blocker');
        }

        // Build HTML
        $blocks_by_type = [];
        foreach ($notifications as $notification) {
            $blocks_by_type[$notification->block_type][] = $notification;
        }
        
        $summary_html = '<p style="font-size: 16px; line-height: 1.6;">' . $intro_text . '</p>';
        $summary_html .= '<h3 style="margin-top: 25px; margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 5px;">' . esc_html__('Summary by Block Type', 'advanced-ip-blocker') . '</h3><ul>';
        
        foreach ($blocks_by_type as $block_type => $blocks) {
            $type_capitalized = ucfirst($block_type);
            $block_count = count($blocks);
            /* translators: 1: Block type, 2: Count. */
            $summary_html .= '<li><strong>' . esc_html($type_capitalized) . ':</strong> ' . sprintf(esc_html(_n('%d item', '%d items', $block_count, 'advanced-ip-blocker')), $block_count) . '</li>';
        }
        $summary_html .= '</ul>';
        
        $summary_html .= '<h3 style="margin-top: 25px; margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 5px;">' . esc_html__('Recent Details', 'advanced-ip-blocker') . '</h3>';
        
        // Table Headers
        $col_1 = ($type === 'signature') ? esc_html__('Hash', 'advanced-ip-blocker') : esc_html__('Blocked IP', 'advanced-ip-blocker');
        
        $summary_html .= '<table style="width: 100%; border-collapse: collapse;"><thead><tr style="background-color: #f9f9f9;">' .
                        '<th style="padding: 8px; border: 1px solid #ddd; text-align: left;">' . esc_html__('Time', 'advanced-ip-blocker') . '</th>' .
                        '<th style="padding: 8px; border: 1px solid #ddd; text-align: left;">' . $col_1 . '</th>' .
                        '<th style="padding: 8px; border: 1px solid #ddd; text-align: left;">' . esc_html__('Reason', 'advanced-ip-blocker') . '</th>' .
                        '</tr></thead><tbody>';

        $details_limit = 20;
        $limited_notifications = array_slice($notifications, -$details_limit);

        foreach ($limited_notifications as $notification) {
            $formatted_time = date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($notification->timestamp));
            
            $col_1_val = $notification->ip;
            if ($type === 'signature') {
                $col_1_val = substr($col_1_val, 0, 8) . '...';
            }

            $summary_html .= '<tr>' .
                            '<td style="padding: 8px; border: 1px solid #ddd;">' . esc_html($formatted_time) . '</td>' .
                            '<td style="padding: 8px; border: 1px solid #ddd;"><code>' . esc_html($col_1_val) . '</code></td>' .
                            '<td style="padding: 8px; border: 1px solid #ddd;">' . esc_html($notification->reason) . '</td>' .
                            '</tr>';
        }
        $summary_html .= '</tbody></table>';

        $button_url = admin_url('options-general.php?page=advaipbl_settings_page&tab=blocked_ips');
        if ($type === 'signature') {
            $button_url = admin_url('admin.php?page=advaipbl_settings_page&tab=ip_management&sub-tab=blocked_signatures');
        }

        $button_text = ($type === 'signature') ? __('Manage Signatures', 'advanced-ip-blocker') : __('Manage All Blocked IPs', 'advanced-ip-blocker');

        $summary_html .= '<table style="width: 100%; text-align: center; margin-top: 30px;"><tr><td>' .
                        '<a href="' . esc_url($button_url) . '" style="background-color: #2271b1; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">' . esc_html($button_text) . '</a>' .
                        '</td></tr></table>';

        $body = $this->get_html_email_template($template_title, $summary_html);
        add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        $sent = wp_mail($to, $email_subject, $body);
        remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        
        if ($sent) {
            /* translators: 1: Summary type (standard/signature), 2: Recipient email address. */
            $this->plugin->log_event(sprintf(__('Security summary (%1$s) sent to %2$s.', 'advanced-ip-blocker'), $type, $to), 'info');
        } else {
            /* translators: 1: Summary type (standard/signature), 2: Recipient email address. */
            $this->plugin->log_event(sprintf(__('FAILED to send security summary (%1$s) to %2$s.', 'advanced-ip-blocker'), $type, $to), 'error');
        }
    }

    /**
     * Sends an instant block notification (Email/Push) or queues it.
     */
    public function notify_block($ip, $type, $reason, $reason_label = '', $extra_data = []) {
        $options = $this->plugin->options;
        if (empty($reason_label)) {
            $reason_label = ucwords(str_replace('_', ' ', $type));
        }

        // Get Location
        $location_data = $this->plugin->geolocation_manager->fetch_location($ip);
        
        // --- PUSH NOTIFICATION LOGIC ---
        if (!empty($options['enable_push_notifications'])) {
            $is_critical_block = !in_array($type, ['404', '403', 'login'], true);
            $send_this_push = empty($options['push_critical_only']) || ($options['push_critical_only'] === '1' && $is_critical_block);

            if ($send_this_push) {
                $site_name = get_bloginfo('name');
                $message_lines = [ sprintf('*:shield: [%s] Security Alert*', $site_name) ];
                $message_lines[] = sprintf('> • *Blocked Entry:* `%s`', $ip);
                if ($location_data && empty($location_data['error'])) {
                    $location_str = ($location_data['city'] ?? '') . ', ' . ($location_data['country'] ?? '');
                    $message_lines[] = sprintf('> • *Location:* %s (%s)', trim($location_str, ', '), $location_data['country_code'] ?? 'N/A');
                }
                $message_lines[] = sprintf('> • *Reason:* %s', $reason_label);
                $message_lines[] = sprintf('> • *Details:* %s', $reason);
                
                $duration_minutes = 0;
                
                if (isset($extra_data['duration_seconds'])) {
                    $duration_minutes = $extra_data['duration_seconds'] > 0 ? round($extra_data['duration_seconds'] / 60) : 0;
                } else if ($type === 'aib_network') {
                    $duration_minutes = (int) ($options['duration_aib_network'] ?? 1440);
                } else if ($type === 'manual') {
                    // Manual blocks with potential legacy expiry are treated as permanent
                    $duration_minutes = 0; 
                } else {
                    // Default for other types
                    $duration_minutes = (int) ($options['duration_' . $type] ?? 1440);
                }

                // Treat as Permanent if duration > 1 year
                /* translators: %d: Duration minutes. */
                $duration_text = ($duration_minutes <= 0 || $duration_minutes > 525600) ? __('Permanent', 'advanced-ip-blocker') : sprintf(__('%d min', 'advanced-ip-blocker'), $duration_minutes);
                $message_lines[] = sprintf('> • *Duration:* %s', $duration_text);
                
                $request_uri = $extra_data['uri'] ?? $this->plugin->get_current_request_uri();
                if (!empty($request_uri)) { $message_lines[] = sprintf('> • *URI:* `%s`', $request_uri); }
                
                // Note: user_agent could be passed in extra_data or fetched from main.
                $ua = $extra_data['user_agent'] ?? $this->plugin->get_user_agent();
                if ($ua) { $message_lines[] = sprintf('> • *User Agent:* `%s`', $ua); }
                
                $this->execute_webhook_send(implode("\n", $message_lines));
            }
        }

        // --- EMAIL LOGIC ---
        $frequency = $options['notification_frequency'] ?? 'disabled';
        if ( empty($options['enable_email_notifications']) || '1' !== $options['enable_email_notifications'] || 'disabled' === $frequency) {
            return;
        }

        if ($frequency === 'instant') {
            $to = !empty($options['notification_email']) && is_email($options['notification_email']) ? $options['notification_email'] : get_option('admin_email');
            $site_name = get_bloginfo('name');
            /* translators: %s: Site name. */
            $email_subject = sprintf(__('[%s] Security Alert: Entry Automatically Blocked', 'advanced-ip-blocker'), $site_name);
            $template_title = __('Security Alert: Entry Blocked', 'advanced-ip-blocker');
            $duration_minutes = 0;
            
            if ( isset($extra_data['duration_seconds']) ) {
                $duration_minutes = $extra_data['duration_seconds'] > 0 ? round($extra_data['duration_seconds'] / 60) : 0;
            } else if ($type !== 'manual') {
                $duration_minutes = (int) ($options['duration_' . $type] ?? 1440);
            }

            // Treat as Permanent if duration > 1 year
            /* translators: %d: Duration minutes. */
            $duration_text = ($duration_minutes <= 0 || $duration_minutes > 525600) ? __('Permanent', 'advanced-ip-blocker') : sprintf(__('%d minutes', 'advanced-ip-blocker'), $duration_minutes);
            $button_url = admin_url( 'admin.php?page=advaipbl_settings_page-ip-management&sub-tab=blocked_ips' );
            
            $content_html = '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__( "An entry has been automatically blocked on your website.", 'advanced-ip-blocker' ) . '</p>' .
                '<table style="width: 100%; border-collapse: collapse; margin-top: 20px;">' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9; width: 150px;"><strong>' . esc_html__( 'Blocked Entry', 'advanced-ip-blocker' ) . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html( $ip ) . '</td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__( 'Date and Time', 'advanced-ip-blocker' ) . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html( date_i18n(get_option('date_format') . ' ' . get_option('time_format')) ) . '</td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__( 'Reason', 'advanced-ip-blocker' ) . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html( $reason ) . '</td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__( 'Block Duration', 'advanced-ip-blocker' ) . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html( $duration_text ) . '</td></tr>' .
                '</table>' .
                '<p style="margin-top: 20px; font-size: 14px; color: #555;">' . esc_html__( 'No action is required on your part. This is just a notification.', 'advanced-ip-blocker' ) . '</p>'.
                '<table style="width: 100%; text-align: center; margin-top: 30px;"><tr><td>' .
                '<a href="' . esc_url( $button_url ) . '" style="background-color: #2271b1; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">' . esc_html__( 'View Blocked IPs', 'advanced-ip-blocker' ) . '</a>' .
                '</td></tr></table>';
            
            $body = $this->get_html_email_template( $template_title, $content_html );
            add_filter( 'wp_mail_content_type', [ $this, 'set_html_mail_content_type' ] );
            wp_mail( $to, $email_subject, $body );
            remove_filter( 'wp_mail_content_type', [ $this, 'set_html_mail_content_type' ] );
        } else {
            global $wpdb;
            $table_name = $wpdb->prefix . 'advaipbl_notifications_queue';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            @$wpdb->insert($table_name, [ 'timestamp' => current_time('mysql', 1), 'ip' => $ip, 'block_type' => $type, 'reason' => $reason ]);
        }
    }

    /**
     * Sends Lockdown Notification (Email + Push).
     */
    public function send_lockdown_notification($endpoint_key, $duration_minutes, $threshold) {
        $options = $this->plugin->options;
        $site_name = get_bloginfo('name');
        $endpoint_name = strtoupper($endpoint_key);

        // --- Push Notification ---
        if (!empty($options['enable_push_notifications'])) {
            $message_lines = [
                sprintf('*:lock: [%s] Endpoint Lockdown Activated*', $site_name),
                '> An automated defense system has been activated due to a sustained attack.',
                /* translators: $s: Endpoint name. */
                sprintf('> • *Protected Endpoint:* `%s`', $endpoint_name),
                /* translators: $d: Threshold number. */
                sprintf('> • *Reason:* More than %d suspicious blocks detected recently.', $threshold),
                /* translators: $d: Minutes. */
                sprintf('> • *Action:* All new traffic to this endpoint will be challenged for the next %d minutes.', $duration_minutes),
            ];
            $this->execute_webhook_send(implode("\n", $message_lines));
        }

        // --- Email Notification ---
        if (!empty($options['enable_email_notifications']) && isset($options['notification_frequency']) && $options['notification_frequency'] === 'instant') {
            $to = !empty($options['notification_email']) ? $options['notification_email'] : get_option('admin_email');
            /* translators: 1: Site name, 2: Endpoint name */
            $email_subject = sprintf(__('[%1$s] Security Alert: Endpoint Lockdown Activated for %2$s', 'advanced-ip-blocker'), $site_name, $endpoint_name);
            $template_title = __('Endpoint Lockdown Activated', 'advanced-ip-blocker');
            $button_url = admin_url('admin.php?page=advaipbl_settings_page&tab=logs&sub-tab=security_log');

            $content_html = 
                '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__("An automated defense mechanism, Endpoint Lockdown, has been activated on your website due to a sustained attack.", 'advanced-ip-blocker') . '</p>' .
                '<table style="width: 100%; border-collapse: collapse; margin-top: 20px;">' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9; width: 150px;"><strong>' . esc_html__('Protected Endpoint', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;"><code>' . esc_html($endpoint_name) . '</code></td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__('Reason for Activation', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . sprintf(/* translators: %d: The number of IPs. */esc_html__('More than %d suspicious IP blocks were detected in a short period.', 'advanced-ip-blocker'), $threshold) . '</td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__('Protective Action', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . sprintf(/* translators: %d: The number minutes. */esc_html__('For the next %d minutes, all new, non-whitelisted traffic to this endpoint will be challenged with a JavaScript verifier to filter out bots.', 'advanced-ip-blocker'), $duration_minutes) . '</td></tr>' .
                '</table>' .
                '<p style="margin-top: 20px; font-size: 14px; color: #555;">' . esc_html__('This is an automated response to protect your site. No immediate action is required on your part.', 'advanced-ip-blocker') . '</p>'.
                '<table style="width: 100%; text-align: center; margin-top: 30px;"><tr><td>' .
                '<a href="' . esc_url( $button_url ) . '" style="background-color: #2271b1; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">' . esc_html__( 'View Security Log', 'advanced-ip-blocker' ) . '</a>' .
                '</td></tr></table>';

            $body = $this->get_html_email_template($template_title, $content_html);
            add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
            wp_mail($to, $email_subject, $body);
            remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        }
    }

    /**
     * Sends AbuseIPDB Limit Notification.
     */
    public function send_abuseipdb_limit_email() {
        $options = $this->plugin->options;
        // Solo enviar si las notificaciones por email están activadas
        if (empty($options['enable_email_notifications']) || '1' !== $options['enable_email_notifications']) {
            return;
        }

        $to = !empty($options['notification_email']) ? $options['notification_email'] : get_option('admin_email');
        $site_name = get_bloginfo('name');

        /* translators: %s: Site name. */
        $email_subject = sprintf(__('[%s] Security Alert: AbuseIPDB API Limit Reached', 'advanced-ip-blocker'), $site_name);
        $template_title = __('AbuseIPDB API Limit Reached', 'advanced-ip-blocker');

        $settings_url = admin_url('admin.php?page=advaipbl_settings_page&tab=settings&sub-tab=threat_intelligence');
        
        $content_html = 
            '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__("This is an automated notification to inform you that your website has reached the daily request limit for the AbuseIPDB API.", 'advanced-ip-blocker') . '</p>' .
            '<p style="font-size: 14px; line-height: 1.6;">' . esc_html__("As a result, the real-time IP reputation checking has been temporarily paused. The system will automatically resume checks when the quota resets (typically at 00:00 UTC).", 'advanced-ip-blocker') . '</p>' .
            '<h3 style="margin-top: 25px; margin-bottom: 10px; color: #2271b1;">' . esc_html__('What this means:', 'advanced-ip-blocker') . '</h3>' .
            '<ul style="font-size: 14px; line-height: 1.6; padding-left: 20px;">' .
            '<li>' . esc_html__('Your site remains protected by all other security layers (WAF, Advanced Rules, etc.).', 'advanced-ip-blocker') . '</li>' .
            '<li>' . esc_html__('This is often an indicator of high bot traffic or a distributed attack.', 'advanced-ip-blocker') . '</li>' .
            '</ul>' .
            '<h3 style="margin-top: 25px; margin-bottom: 10px; color: #2271b1;">' . esc_html__('Recommended Actions:', 'advanced-ip-blocker') . '</h3>' .
            '<ul style="font-size: 14px; line-height: 1.6; padding-left: 20px;">' .
            '<li>' . /* translators: %s: Link to documentation. Do not translate the URLs. */sprintf(wp_kses(__('Consider verifying your domain with AbuseIPDB to increase your free daily limit from 1,000 to 3,000 checks. <a href="%s" target="_blank">Learn how</a>.', 'advanced-ip-blocker'), ['a' => ['href' => [], 'target' => []]]), 'https://advaipbl.com/docs/abuseipdb-integration-guide/') . '</li>' .
            '<li>' . /* translators: %s: Link to pricing page. Do not translate the URLs. */sprintf(wp_kses(__('For high-traffic sites, consider upgrading to a <a href="%s" target="_blank">paid AbuseIPDB plan</a> for a higher limit.', 'advanced-ip-blocker'), ['a' => ['href' => [], 'target' => []]]), 'https://www.abuseipdb.com/pricing') . '</li>' .
            '</ul>' .
            '<table style="width: 100%; text-align: center; margin-top: 30px;"><tr><td>' .
            '<a href="' . esc_url($settings_url) . '" style="background-color: #2271b1; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">' . esc_html__('Manage Settings', 'advanced-ip-blocker') . '</a>' .
            '</td></tr></table>';

        $body = $this->get_html_email_template($template_title, $content_html);
        add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        wp_mail($to, $email_subject, $body);
        remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        
        // --- Push Notification ---
        if (!empty($options['enable_push_notifications'])) {
            $doc_link = 'https://advaipbl.com/docs/abuseipdb-integration-guide/';
            $pricing_link = 'https://www.abuseipdb.com/pricing';

            $message_lines = [
                sprintf('*:warning: [%s] %s*', $site_name, __('Security Alert: AbuseIPDB API Limit Reached', 'advanced-ip-blocker')),
                '> ' . __('Your website has reached its daily request limit for the AbuseIPDB API.', 'advanced-ip-blocker'),
                '> ' . __('Real-time IP reputation checking will be temporarily paused.', 'advanced-ip-blocker'),
                sprintf(
                    /* translators: 1: Link to documentation, 2: Link to pricing page. Do not translate the URLs. */
                    '> • *Action Required:* Consider <%1$s|verifying your domain> to triple your free quota or <%2$s|upgrading your plan>.',
                    $doc_link,
                    $pricing_link
                ),
            ];
            $this->execute_webhook_send(implode("\n", $message_lines));
        }
    }

    /**
     * Executes webhook send.
     */
    public function execute_webhook_send($message) {
        $options = $this->plugin->options;
        if (empty($options['enable_push_notifications'])) {
            return false;
        }

        $raw_urls = $options['push_webhook_urls'] ?? '';
        if (empty(trim($raw_urls))) {
            return false;
        }

        $urls = array_filter(array_map('trim', explode("\n", $raw_urls)));
        if (empty($urls)) {
            return false;
        }

        $payload = [
            'content' => $message,
            'text'    => $message,
        ];

        $args = [
            'body'    => wp_json_encode($payload),
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'timeout' => 10,
        ];

        $success = false;
        foreach ($urls as $url) {
            $response = wp_remote_post($url, $args);

            if (is_wp_error($response)) {
                $this->plugin->log_event('Failed to send push notification: ' . $response->get_error_message(), 'error', ['webhook_url' => $url]);
            } elseif (wp_remote_retrieve_response_code($response) >= 300) {
                $this->plugin->log_event('Push notification sent, but received an error response code: ' . wp_remote_retrieve_response_code($response), 'warning', ['webhook_url' => $url]);
            } else {
                $success = true;
            }
        }
        
        return $success;
    }

    /**
     * Standard HTML Email Template (Premium Design).
     */
    public function get_html_email_template($title, $content) {
        $logo_url = plugin_dir_url(dirname(__FILE__)) . 'assets/img/logo-email.png';
        
        ob_start();
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title><?php echo esc_html($title); ?></title>
            <style>
                body { margin: 0; padding: 0; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f1f1f1; color: #444444; }
                .email-container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-top: 20px; margin-bottom: 20px; }
                .email-header { background-color: #ffffff; padding: 20px; text-align: center; border-bottom: 1px solid #eeeeee; }
                .email-header img { max-width: 220px; height: auto; border: 0; display: inline-block; vertical-align: middle; }
                .email-body { padding: 30px; line-height: 1.6; font-size: 14px; color: #333333; }
                .email-body h2 { color: #1d2327; font-size: 24px; margin-top: 0; margin-bottom: 15px; font-weight: 700; }
                .email-footer { background-color: #f9f9f9; padding: 20px; text-align: center; font-size: 12px; color: #787c82; border-top: 1px solid #eeeeee; }
                .email-footer a { color: #787c82; text-decoration: none; }
                .btn { display: inline-block; padding: 10px 20px; background-color: #2271b1; color: #ffffff; text-decoration: none; border-radius: 4px; font-weight: bold; margin-top: 20px; }
                .btn:hover { background-color: #135e96; }
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="email-header">
                    <img src="<?php echo esc_url($logo_url); ?>" alt="Advanced IP Blocker Logo">
                </div>
                
                <div class="email-body">
                    <h2><?php echo esc_html($title); ?></h2>
                    <div class="content">
                        <?php echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                    </div>
                </div>
                
                <div class="email-footer">
                    <p style="margin: 0;"><?php esc_html_e('This email was generated by the Advanced IP Blocker plugin.', 'advanced-ip-blocker'); ?></p>
                    <p style="margin: 5px 0 0;">
                        <?php 
                        $settings_url = admin_url('admin.php?page=advaipbl_settings_page');
                        
                        /* translators: %s: URL to settings page */
                        $unsubscribe_text = __('To unsubscribe from these updates, please visit the <a href="%s" style="color: #2271b1;">settings page</a>.', 'advanced-ip-blocker');
                        
                        printf(
                            wp_kses(
                                $unsubscribe_text,
                                ['a' => ['href' => [], 'style' => []]]
                            ),
                            esc_url($settings_url)
                        ); 
                        ?>
                    </p>
                    <p style="margin: 10px 0 0; font-weight: bold;">
                        <?php 
                        printf(
                            /* translators: %1$s: Plugin Name, %2$s: Plugin Version */
                            esc_html__('Sent by %1$s v%2$s', 'advanced-ip-blocker'),
                            'Advanced IP Blocker',
                            esc_html(ADVAIPBL_VERSION)
                        ); 
                        ?>
                    </p>
                </div>
            </div>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    /**
     * Envía notificaciones (Email/Push) cuando una nueva firma maliciosa es identificada.
     */
    public function send_signature_flagged_notification($signature_hash, $reason, $user_agent = 'N/A') {
        $short_hash = substr($signature_hash, 0, 12) . '...';
        $site_name = get_bloginfo('name');
        
        // --- Notificación Push (Webhook) ---
        if (!empty($this->plugin->options['enable_push_notifications'])) {
            $message_lines = [
                sprintf('*:dna: [%s] New Attack Signature Identified*', $site_name),
                '> A new attack pattern has been automatically identified and is now being challenged.',
                sprintf('> • *Signature Hash:* `%s`', $short_hash),
                sprintf('> • *Reason:* %s', $reason),
                sprintf('> • *Sample User-Agent:* `%s`', $user_agent),
            ];
            $this->execute_webhook_send(implode("\n", $message_lines));
        }

        // --- Notificación por Email ---
        if (!empty($this->plugin->options['enable_email_notifications'])) {
            $options = $this->plugin->options;
            $to = !empty($options['notification_email']) ? $options['notification_email'] : get_option('admin_email');
            /* translators: %s: Site name. */
            $email_subject = sprintf(__('[%s] Security Alert: New Attack Signature Identified', 'advanced-ip-blocker'), $site_name);
            $template_title = __('New Attack Signature Identified', 'advanced-ip-blocker');
            
            $button_url = admin_url('admin.php?page=advaipbl_settings_page&tab=ip_management&sub-tab=blocked_signatures');

            $content_html = 
                '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__("The plugin's analysis engine has automatically identified a new distributed attack pattern. Requests matching this signature will now be challenged.", 'advanced-ip-blocker') . '</p>' .
                '<table style="width: 100%; border-collapse: collapse; margin-top: 20px;">' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9; width: 150px;"><strong>' . esc_html__('Signature Hash', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;"><code>' . esc_html($short_hash) . '</code></td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__('Reason', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html($reason) . '</td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__('Sample User-Agent', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd; word-break: break-all;">' . esc_html($user_agent) . '</td></tr>' .
                '</table>' .
                '<p style="margin-top: 20px; font-size: 14px; color: #555;">' . esc_html__('You can view and manage all active signatures from the dashboard.', 'advanced-ip-blocker') . '</p>'.
                '<table style="width: 100%; text-align: center; margin-top: 30px;"><tr><td>' .
                '<a href="' . esc_url( $button_url ) . '" style="background-color: #2271b1; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">' . esc_html__( 'Manage Signatures', 'advanced-ip-blocker' ) . '</a>' .
                '</td></tr></table>';

            $body = $this->get_html_email_template($template_title, $content_html);
            add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
            wp_mail($to, $email_subject, $body);
            remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        }
    }

    /**
     * Handles sending a test email.
     */
    public function send_test_email($to) {
        $site_name = get_bloginfo('name');
        $settings_url = admin_url('options-general.php?page=advaipbl_settings_page');

        /* translators: %s: The name of the website. */
        $email_subject = sprintf(__('[%s] Welcome & Quick Setup Guide for Advanced IP Blocker', 'advanced-ip-blocker'), $site_name);
        $template_title = __('Welcome & Quick Setup Guide', 'advanced-ip-blocker');

        $content_html = 
            '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__('Thank you for using Advanced IP Blocker! This email confirms your email settings are working. Here is a quick guide to get the most out of the plugin:', 'advanced-ip-blocker') . '</p>' .
            '<h3 style="margin-top: 25px; margin-bottom: 10px; color: #2271b1;">' . esc_html__('Step 1: Verify Whitelisted IPs', 'advanced-ip-blocker') . '</h3>' .
            '<p style="font-size: 14px; line-height: 1.6;">' .
            sprintf(
				/* translators: %s: Link URL to the Status & Debug tab. */
                wp_kses(__('This is the most important step. Go to the <a href="%s">Status & Debug tab</a> to confirm your IP is whitelisted.', 'advanced-ip-blocker'), ['a' => ['href' => []]]),
                esc_url(add_query_arg('tab', 'status', $settings_url))
            ) . '</p>';

        $body = $this->get_html_email_template($template_title, $content_html);
        add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        $sent = wp_mail($to, $email_subject, $body);
        remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        
        return $sent;
    }

    /**
     * Handles sending a test push notification.
     */
    public function send_test_push() {
        $options = $this->plugin->options;
        $webhook_urls_str = $options['push_webhook_urls'] ?? '';
        $webhook_urls = array_filter(array_map('trim', explode("\n", $webhook_urls_str)));
        
        if (empty($webhook_urls)) {
            return false;
        }

        $site_name = get_bloginfo('name');
        $message_lines = [
            sprintf('*:rocket: [%s] Test Notification*', $site_name),
            '> ' . esc_html__('This is a test notification from Advanced IP Blocker.', 'advanced-ip-blocker'),
            '> • *Status:* Working successfully.',
            '> • *Time:* ' . current_time('mysql'),
        ];
        $message = implode("\n", $message_lines);

        return $this->execute_webhook_send($message);
    }

    /**
     * Sends 2FA Activation/Deactivation Notification.
     * 
     * @param string $action 'activated' or 'deactivated'
     * @param WP_User $user The user object
     */
    public function send_2fa_notification_email($action, $user) {
        $options = $this->plugin->options;
        if (empty($options['enable_email_notifications']) || '1' !== $options['enable_email_notifications']) {
            return;
        }

        $to = $user->user_email;
        $site_name = get_bloginfo('name');
        $subject_action = ($action === 'activated') ? __('Activated', 'advanced-ip-blocker') : __('Deactivated', 'advanced-ip-blocker');
        
        /* translators: 1: Site name, 2: Action (Activated/Deactivated) */
        $email_subject = sprintf(__('[%1$s] Security Alert: 2FA %2$s', 'advanced-ip-blocker'), $site_name, $subject_action);
        
        /* translators: %s: Action (Activated/Deactivated) */
        $template_title = sprintf(__('Two-Factor Authentication %s', 'advanced-ip-blocker'), $subject_action);

        $date = date_i18n(get_option('date_format') . ' ' . get_option('time_format'));
        
        $content_html = '<p style="font-size: 16px; line-height: 1.6;">' . 
            sprintf(
                /* translators: 1: User display name, 2: Action (activated/deactivated) */
                esc_html__('Hello %1$s, use this email to confirm that Two-Factor Authentication has been %2$s for your account.', 'advanced-ip-blocker'),
                esc_html($user->display_name),
                '<strong>' . esc_html(strtolower($subject_action)) . '</strong>'
            ) . '</p>';

        $content_html .= '<table style="width: 100%; border-collapse: collapse; margin-top: 20px;">' .
            '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9; width: 150px;"><strong>' . esc_html__('Account', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html($user->user_login) . '</td></tr>' .
            '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__('Date', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html($date) . '</td></tr>' .
            '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__('Status', 'advanced-ip-blocker') . '</strong></td><td style="padding: 8px; border: 1px solid #ddd; color: ' . ($action === 'activated' ? 'green' : 'red') . ';">' . esc_html($subject_action) . '</td></tr>' .
            '</table>';
            
        if ($action === 'deactivated') {
             $content_html .= '<p style="margin-top: 20px; font-size: 14px; color: #d63638;">' . esc_html__('If you did not perform this action, please contact the site administrator immediately and change your password.', 'advanced-ip-blocker') . '</p>';
        }

        $body = $this->get_html_email_template($template_title, $content_html);
        add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        wp_mail($to, $email_subject, $body);
        remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
    }
    public function set_html_mail_content_type() {
        return 'text/html';
    }

    /**
     * Sends a batch notification for multiple detected signatures.
     */
    public function send_signature_batch_notification($signatures) {
        $options = $this->plugin->options;
        $frequency = $options['signature_notification_frequency'] ?? 'instant';

        if ($frequency === 'disabled') {
            return;
        }

        // Handle Daily/Weekly queuing
        if ($frequency === 'daily' || $frequency === 'weekly') {
            global $wpdb;
            $table_name = $wpdb->prefix . 'advaipbl_notifications_queue';
            foreach ($signatures as $sig) {
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_name, [
                    'timestamp' => current_time('mysql', 1),
                    'ip' => $sig['hash'], // Store hash as IP for identification
                    'block_type' => 'signature',
                    'reason' => $sig['reason']
                ]);
            }
            return;
        }

        // Handle Instant (Batched) Email
        if ($frequency === 'instant') {
            // Determine Recipient
            $recipient_type = $options['signature_notification_recipient'] ?? 'default';
            $to = get_option('admin_email');
            
            if ($recipient_type === 'default') {
                $to = !empty($options['notification_email']) ? $options['notification_email'] : get_option('admin_email');
            } elseif ($recipient_type === 'custom') {
                $to = !empty($options['signature_notification_custom_email']) ? $options['signature_notification_custom_email'] : get_option('admin_email');
            }

            if (!is_email($to)) {
                $to = get_option('admin_email');
            }

            $site_name = get_bloginfo('name');
            $count = count($signatures);
            /* translators: 1: Site name, 2: Number of signatures */
            $email_subject = sprintf(__('[%1$s] Security Alert: %2$d New Attack Signatures Identified', 'advanced-ip-blocker'), $site_name, $count);
            /* translators: %d: Number of signatures */
            $template_title = sprintf(__('Attack Signatures Identified (%d)', 'advanced-ip-blocker'), $count);

            $button_url = admin_url('admin.php?page=advaipbl_settings_page&tab=ip_management&sub-tab=blocked_signatures');

            $content_html = '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__("The plugin's analysis engine has identified new distributed attack patterns. Requests matching these signatures will now be challenged.", 'advanced-ip-blocker') . '</p>';
            
            $content_html .= '<table style="width: 100%; border-collapse: collapse; margin-top: 20px;">' .
                '<thead><tr style="background-color: #f9f9f9;">' .
                '<th style="padding: 8px; border: 1px solid #ddd; text-align: left;">' . esc_html__('Hash', 'advanced-ip-blocker') . '</th>' .
                '<th style="padding: 8px; border: 1px solid #ddd; text-align: left;">' . esc_html__('Reason', 'advanced-ip-blocker') . '</th>' .
                '<th style="padding: 8px; border: 1px solid #ddd; text-align: left;">' . esc_html__('Count', 'advanced-ip-blocker') . '</th>' .
                '</tr></thead><tbody>';

            foreach ($signatures as $sig) {
                $short_hash = substr($sig['hash'], 0, 8) . '...';
                $content_html .= '<tr>' .
                    '<td style="padding: 8px; border: 1px solid #ddd;"><code>' . esc_html($short_hash) . '</code></td>' .
                    '<td style="padding: 8px; border: 1px solid #ddd;">' . esc_html($sig['reason']) . '</td>' .
                    /* translators: %d: Number of IPs. */
                    '<td style="padding: 8px; border: 1px solid #ddd;">' . sprintf(esc_html__('%d IPs', 'advanced-ip-blocker'), $sig['count']) . '</td>' .
                    '</tr>';
            }
            $content_html .= '</tbody></table>';

             $content_html .= '<table style="width: 100%; text-align: center; margin-top: 30px;"><tr><td>' .
                '<a href="' . esc_url( $button_url ) . '" style="background-color: #2271b1; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">' . esc_html__( 'Manage Signatures', 'advanced-ip-blocker' ) . '</a>' .
                '</td></tr></table>';

            $body = $this->get_html_email_template($template_title, $content_html);
            add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
            wp_mail($to, $email_subject, $body);
            remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
        }
        
        // Push Notification (Summary)
        if (!empty($options['enable_push_notifications'])) {
             $site_name = get_bloginfo('name');
             $count = count($signatures);
             $message_lines = [
                sprintf('*:dna: [%s] Attack Signatures Identified*', $site_name),
                sprintf('> %d new attack patterns have been identified and challenged.', $count),
             ];
             // Add details for first 3
             foreach (array_slice($signatures, 0, 3) as $sig) {
                 $short_hash = substr($sig['hash'], 0, 8) . '...';
                 $message_lines[] = sprintf('> • `%s`: %s', $short_hash, $sig['reason']);
             }
             if ($count > 3) {
                 $message_lines[] = sprintf('> • ... and %d more.', $count - 3);
             }
             $this->execute_webhook_send(implode("\n", $message_lines));
        }
    }
}
