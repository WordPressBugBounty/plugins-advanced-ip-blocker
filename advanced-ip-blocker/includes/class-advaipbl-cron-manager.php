<?php

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Class ADVAIPBL_Cron_Manager
 *
 * Handles all WP-Cron scheduling and execution logic.
 */
class ADVAIPBL_Cron_Manager
{
    private $plugin;

    public function __construct($plugin)
    {
        $this->plugin = $plugin;

        add_filter('cron_schedules', [$this, 'add_cron_intervals']);

        add_action('advaipbl_threat_score_decay_event', [$this, 'execute_threat_score_decay']);
        add_action('advaipbl_signature_analysis_event', [$this, 'execute_signature_analysis']);
        add_action('advaipbl_scheduled_scan_event', [$this, 'execute_malware_scan']);
        add_action('advaipbl_update_spamhaus_list_event', [$this, 'update_spamhaus_list']);

        // Note: The following actions are registered in ADVAIPBL_Main::add_hooks() to avoid duplication:

        add_action('advaipbl_daily_fim_scan', [$this->plugin->file_verifier, 'scan_files']);
        add_action('advaipbl_cloudflare_cleanup_event', [$this->plugin->cloudflare_manager, 'clear_all_aib_rules']);
        add_action('advaipbl_cloudflare_sync_event', [$this->plugin->cloudflare_manager, 'sync_blocked_ips']);
        add_action('advaipbl_update_community_list_event', [$this->plugin->community_manager, 'update_list']);
        add_action('advaipbl_community_report_event_v2', [$this->plugin, 'execute_community_report']);
        add_action('advaipbl_update_bot_lists_event', [$this->plugin->bot_verifier, 'fetch_and_cache_bot_lists']);
        add_action('advaipbl_zeroday_sync_event', [$this->plugin, 'sync_zeroday_waf_rules']);
        add_action('advaipbl_zeroday_version_check_event', [$this->plugin, 'check_zeroday_waf_version']);
        add_action('advaipbl_advanced_zeroday_sync_event', [$this->plugin, 'sync_advanced_zeroday_rules']);
        add_action('advaipbl_advanced_zeroday_version_check_event', [$this->plugin, 'check_advanced_zeroday_version']);
        add_action('advaipbl_fim_signatures_sync_event', [$this->plugin, 'sync_fim_signatures']);
        add_action('advaipbl_fim_signatures_version_check_event', [$this->plugin, 'check_fim_signatures_version']);
    }

    /**
     * Adds custom time intervals to WP Cron.
     */
    public function add_cron_intervals($schedules)
    {
        $schedules['advaipbl_6_hours'] = [
            'interval' => 21600,
            'display'  => __('Every 6 Hours (AIB)', 'advanced-ip-blocker')
        ];
        $schedules['advaipbl_3_days'] = [
            'interval' => 259200,
            'display'  => __('Every 3 Days (AIB)', 'advanced-ip-blocker')
        ];
        $schedules['advaipbl_weekly'] = [
            'interval' => 604800,
            'display'  => __('Once Weekly (AIB)', 'advanced-ip-blocker')
        ];

        return $schedules;
    }

    /**
     * Schedules all necessary cron jobs based on settings.
     * Called usually during admin init or settings save.
     */
    public function schedule_jobs()
    {
        if (! wp_next_scheduled('advaipbl_threat_score_decay_event')) {
            wp_schedule_event(time(), 'hourly', 'advaipbl_threat_score_decay_event');
        }

        if (! empty($this->plugin->options['enable_signature_analysis'])) {
            if (! wp_next_scheduled('advaipbl_signature_analysis_event')) {
                wp_schedule_event(time(), 'hourly', 'advaipbl_signature_analysis_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_signature_analysis_event');
        }

        if (!wp_next_scheduled('advaipbl_purge_old_logs_event')) {
            wp_schedule_event(time(), 'daily', 'advaipbl_purge_old_logs_event');
        }

        $freq_main = $this->plugin->options['notification_frequency'] ?? 'daily';

        if ($freq_main !== 'instant' && $freq_main !== 'disabled') {
            if (!wp_next_scheduled('advaipbl_send_summary_email')) {
                $timestamp = strtotime('08:00:00');
                if ($timestamp < time()) {
                    $timestamp += DAY_IN_SECONDS;
                }
                wp_schedule_event($timestamp, $freq_main, 'advaipbl_send_summary_email');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_send_summary_email');
        }

        $freq_sig = $this->plugin->options['signature_notification_frequency'] ?? 'instant';

        if ($freq_sig !== 'instant' && $freq_sig !== 'disabled') {
            if (!wp_next_scheduled('advaipbl_send_signature_summary_email')) {
                $timestamp = strtotime('08:05:00');
                if ($timestamp < time()) {
                    $timestamp += DAY_IN_SECONDS;
                }

                $sig_schedule = ($freq_sig === 'daily' || $freq_sig === 'weekly') ? $freq_sig : 'daily';

                wp_schedule_event($timestamp, $sig_schedule, 'advaipbl_send_signature_summary_email');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_send_signature_summary_email');
        }

        if (!empty($this->plugin->options['allow_telemetry']) && $this->plugin->options['allow_telemetry'] === '1') {
            if (!wp_next_scheduled('advaipbl_send_telemetry_data_event')) {
                $jitter = wp_rand(0, 12 * HOUR_IN_SECONDS);
                wp_schedule_event(time() + $jitter, 'weekly', 'advaipbl_send_telemetry_data_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_send_telemetry_data_event');
        }

        $schedule = wp_get_schedule('advaipbl_update_geoip_db_event');
        if ($schedule === 'weekly' || $schedule === 'three_days' || $schedule === 'advaipbl_weekly') {
            wp_clear_scheduled_hook('advaipbl_update_geoip_db_event');
        }

        if (!empty($this->plugin->options['maxmind_license_key'])) {
            if (!wp_next_scheduled('advaipbl_update_geoip_db_event')) {
                wp_schedule_event(time() + wp_rand(60, 300), 'advaipbl_3_days', 'advaipbl_update_geoip_db_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_update_geoip_db_event');
        }

        if (!wp_next_scheduled('advaipbl_clear_expired_blocks_event')) {
            wp_schedule_event(time(), 'hourly', 'advaipbl_clear_expired_blocks_event');
        }

        if (!wp_next_scheduled('advaipbl_aggregate_rules_metrics')) {
            wp_schedule_event(time(), 'hourly', 'advaipbl_aggregate_rules_metrics');
        }

        if (!wp_next_scheduled('advaipbl_aggregate_challenge_metrics')) {
            wp_schedule_event(time(), 'hourly', 'advaipbl_aggregate_challenge_metrics');
        }

        if (!wp_next_scheduled('advaipbl_cleanup_expired_cache_event')) {
            wp_schedule_event(time(), 'daily', 'advaipbl_cleanup_expired_cache_event');
        }

        $fim_freq = $this->plugin->options['fim_scan_frequency'] ?? 'daily';
        if (!empty($this->plugin->options['enable_fim'])) {
            $current_fim_schedule = wp_get_schedule('advaipbl_daily_fim_scan');
            if ($current_fim_schedule !== $fim_freq) {
                wp_clear_scheduled_hook('advaipbl_daily_fim_scan');
                wp_schedule_event(time() + wp_rand(0, 4 * HOUR_IN_SECONDS), $fim_freq, 'advaipbl_daily_fim_scan');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_daily_fim_scan');
        }

        $enable_scan = $this->plugin->options['enable_scheduled_scans'] ?? '0';

        $scan_freq   = $this->plugin->options['scheduled_scan_frequency'] ?? 'daily';

        $enable_scan_val = $this->plugin->options['enable_scheduled_scans'] ?? '0';
        $scan_freq_val   = $this->plugin->options['scan_frequency'] ?? 'weekly';

        if ($enable_scan_val === '1') {
            if (! wp_next_scheduled('advaipbl_scheduled_scan_event')) {
                $schedule_time = strtotime('tomorrow 00:00:00') + wp_rand(0, 6 * HOUR_IN_SECONDS);
                wp_schedule_event($schedule_time, $scan_freq_val, 'advaipbl_scheduled_scan_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_scheduled_scan_event');
        }

        $next_scan = wp_next_scheduled('advaipbl_scheduled_scan_event');
        if ($enable_scan_val === '1' && $next_scan) {
            $schedule = wp_get_schedule('advaipbl_scheduled_scan_event');
            if ($schedule !== $scan_freq_val) {
                wp_clear_scheduled_hook('advaipbl_scheduled_scan_event');
                $schedule_time = strtotime('tomorrow 00:00:00') + wp_rand(0, 6 * HOUR_IN_SECONDS);
                wp_schedule_event($schedule_time, $scan_freq_val, 'advaipbl_scheduled_scan_event');
            }
        }

        if (! wp_next_scheduled('advaipbl_community_report_event_v2')) {
            wp_clear_scheduled_hook('advaipbl_community_report_event');
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'six_hours', 'advaipbl_community_report_event_v2');
        }

        if (!empty($this->plugin->options['enable_spamhaus_asn']) && '1' === $this->plugin->options['enable_spamhaus_asn']) {
            if (!wp_next_scheduled('advaipbl_update_spamhaus_list_event')) {
                wp_schedule_event(time(), 'daily', 'advaipbl_update_spamhaus_list_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_update_spamhaus_list_event');
        }

        wp_clear_scheduled_hook('advaipbl_update_ai_bot_lists_event');
        if (!empty($this->plugin->options['enable_ai_bot_verification']) && '1' === $this->plugin->options['enable_ai_bot_verification']) {
            if (!wp_next_scheduled('advaipbl_update_bot_lists_event')) {
                wp_schedule_event(time(), 'daily', 'advaipbl_update_bot_lists_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_update_bot_lists_event');
        }

        if (!empty($this->plugin->options['enable_intelligent_waf']) && '1' === $this->plugin->options['enable_intelligent_waf']) {
            if (!wp_next_scheduled('advaipbl_zeroday_sync_event')) {
                wp_schedule_event(time() + wp_rand(0, 4 * HOUR_IN_SECONDS), 'daily', 'advaipbl_zeroday_sync_event');
            }
            if (!wp_next_scheduled('advaipbl_zeroday_version_check_event')) {
                wp_schedule_event(time() + wp_rand(0, HOUR_IN_SECONDS), 'hourly', 'advaipbl_zeroday_version_check_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_zeroday_sync_event');
            wp_clear_scheduled_hook('advaipbl_zeroday_version_check_event');
        }

        if (!empty($this->plugin->options['enable_cloud_advanced_rules']) && '1' === $this->plugin->options['enable_cloud_advanced_rules']) {
            if (!wp_next_scheduled('advaipbl_advanced_zeroday_sync_event')) {
                wp_schedule_event(time() + wp_rand(0, 4 * HOUR_IN_SECONDS), 'daily', 'advaipbl_advanced_zeroday_sync_event');
            }
            if (!wp_next_scheduled('advaipbl_advanced_zeroday_version_check_event')) {
                wp_schedule_event(time() + wp_rand(0, HOUR_IN_SECONDS), 'hourly', 'advaipbl_advanced_zeroday_version_check_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_advanced_zeroday_sync_event');
            wp_clear_scheduled_hook('advaipbl_advanced_zeroday_version_check_event');
        }

        if (!empty($this->plugin->options['enable_fim']) && '1' === $this->plugin->options['enable_fim']) {
            if (!wp_next_scheduled('advaipbl_fim_signatures_sync_event')) {
                wp_schedule_event(time() + wp_rand(0, 4 * HOUR_IN_SECONDS), 'daily', 'advaipbl_fim_signatures_sync_event');
            }
            if (!wp_next_scheduled('advaipbl_fim_signatures_version_check_event')) {
                wp_schedule_event(time() + wp_rand(0, HOUR_IN_SECONDS), 'hourly', 'advaipbl_fim_signatures_version_check_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_fim_signatures_sync_event');
            wp_clear_scheduled_hook('advaipbl_fim_signatures_version_check_event');
        }

        $schedule = wp_get_schedule('advaipbl_update_community_list_event');
        if ($schedule === 'six_hours') {
            wp_clear_scheduled_hook('advaipbl_update_community_list_event');
        }

        if (! wp_next_scheduled('advaipbl_update_community_list_event')) {
            wp_schedule_event(time() + MINUTE_IN_SECONDS, 'advaipbl_6_hours', 'advaipbl_update_community_list_event');
        }

        $schedule = wp_get_schedule('advaipbl_community_report_event_v2');
        if ($schedule === 'six_hours') {
            wp_clear_scheduled_hook('advaipbl_community_report_event_v2');
        }

        if (! wp_next_scheduled('advaipbl_community_report_event_v2')) {
            wp_schedule_event(time() + (2 * HOUR_IN_SECONDS), 'advaipbl_6_hours', 'advaipbl_community_report_event_v2');
        }

        if (!empty($this->plugin->options['enable_cloudflare']) && '1' === $this->plugin->options['enable_cloudflare']) {
            if (! wp_next_scheduled('advaipbl_cloudflare_cleanup_event')) {
                wp_schedule_event(time() + wp_rand(0, DAY_IN_SECONDS), 'daily', 'advaipbl_cloudflare_cleanup_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_cloudflare_cleanup_event');
        }

        // 17. Cloudflare Sync (Hourly if enabled) - CRITICAL FIX
        if (!empty($this->plugin->options['enable_cloudflare']) && '1' === $this->plugin->options['enable_cloudflare']) {
            if (! wp_next_scheduled('advaipbl_cloudflare_sync_event')) {
                wp_schedule_event(time(), 'hourly', 'advaipbl_cloudflare_sync_event');
            }
        } else {
            wp_clear_scheduled_hook('advaipbl_cloudflare_sync_event');
        }

        $crons = _get_cron_array();
        $count = 0;
        if (is_array($crons)) {
            foreach ($crons as $timestamp => $cronhooks) {
                if (isset($cronhooks['advaipbl_update_community_list_event'])) {
                    $count++;
                }
            }
        }

        if ($count > 1) {
            wp_clear_scheduled_hook('advaipbl_update_community_list_event');
            wp_schedule_event(time() + MINUTE_IN_SECONDS, 'advaipbl_6_hours', 'advaipbl_update_community_list_event');
        }

        delete_transient('advaipbl_crons_scheduled');
        set_transient('advaipbl_crons_scheduled_v866', true, DAY_IN_SECONDS);
    }

    /**
     * Executes Threat Score Decay.
     */
    public function execute_threat_score_decay()
    {
        if (!empty($this->plugin->threat_score_manager)) {
            $decay_points = (int) ($this->plugin->options['threat_score_decay_points'] ?? 10);
            $inactive_hours = (int) ($this->plugin->options['threat_score_decay_period'] ?? 1);
            $inactive_seconds = $inactive_hours * HOUR_IN_SECONDS;

            $this->plugin->threat_score_manager->decay_scores($decay_points, $inactive_seconds);
        }
    }

    /**
     * Executes Signature Analysis.
     */
    public function execute_signature_analysis()
    {
        if (empty($this->plugin->options['enable_signature_analysis'])) {
            return;
        }

        $ip_threshold = (int) ($this->plugin->options['signature_ip_threshold'] ?? 5);
        $analysis_window_hours = (int) ($this->plugin->options['signature_analysis_window'] ?? 1);
        $rule_ttl_hours = (int) ($this->plugin->options['signature_rule_ttl'] ?? 24);

        if (!empty($this->plugin->fingerprint_manager)) {
            $this->plugin->fingerprint_manager->analyze_and_flag_signatures(
                $ip_threshold,
                $analysis_window_hours * HOUR_IN_SECONDS,
                $rule_ttl_hours * HOUR_IN_SECONDS
            );
        }
    }

    /**
     * Executes Scheduled Malware Scan.
     */
    public function execute_malware_scan()
    {
        if (!empty($this->plugin->site_scanner)) {
            $this->plugin->site_scanner->run_full_scan_and_email(null, false);
        }
    }

    /**
     * Updates Spamhaus List.
     */
    public function update_spamhaus_list()
    {
        if (empty($this->plugin->options['enable_spamhaus_asn']) || '1' !== $this->plugin->options['enable_spamhaus_asn']) {
            return;
        }

        $this->plugin->update_spamhaus_list();
    }
}
