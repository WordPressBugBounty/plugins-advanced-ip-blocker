<?php

if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Fingerprint_Manager
{
    private $main_class;

    public function __construct(ADVAIPBL_Main $main_class)
    {
        $this->main_class = $main_class;
    }

    /**
     * Generates a unique "signature" (fingerprint) for the current request.
     * The signature is based on a combination of headers and request characteristics.
     *
     * @return string The SHA256 hash representing the request signature.
     */
    public function generate_signature()
    {
        $signature_parts = [];

        $signature_parts[] = $this->main_class->get_user_agent();

        $signature_parts[] = isset($_SERVER['HTTP_ACCEPT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'])) : 'no-accept';
        $signature_parts[] = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'])) : 'no-language';
        $signature_parts[] = isset($_SERVER['HTTP_ACCEPT_ENCODING']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_ENCODING'])) : 'no-encoding';
        $signature_string = implode('|', $signature_parts);

        return hash('sha256', $signature_string);
    }

    /**
     * Extracts relevant request headers to save in the log.
     *
     * @return string A JSON string with the headers.
     */
    public function get_request_headers_for_log()
    {
        $headers_to_log = [
            'Accept', 'Accept-Language', 'Accept-Encoding', 'Referer', 'Origin',
            'CF-Connecting-IP', 'X-Forwarded-For', 'X-Real-IP'
        ];

        $collected_headers = [];
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $header = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                if (in_array($header, $headers_to_log)) {
                    $collected_headers[$header] = $value;
                }
            }
        }

        return wp_json_encode($collected_headers);
    }

    /**
 * Analyzes request logs to find and flag malicious signatures.
 * Executes via WP-Cron.
 *
 * @param int $ip_threshold          Minimum distinct IPs to flag a signature.
 * @param int $analysis_window_seconds Time period (backwards) to analyze.
 * @param int $rule_ttl_seconds        Time-to-live (TTL) for a new signature rule.
 */
    public function analyze_and_flag_signatures($ip_threshold, $analysis_window_seconds, $rule_ttl_seconds)
    {
        global $wpdb;
        $log_table = $wpdb->prefix . 'advaipbl_request_log';
        $signatures_table = $wpdb->prefix . 'advaipbl_malicious_signatures';

        // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query($wpdb->prepare("DELETE FROM {$signatures_table} WHERE expires_at <= %d", time()));
        // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

        $start_time = time() - $analysis_window_seconds;

        // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $suspicious_signatures = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT signature_hash, COUNT(DISTINCT ip_hash) as ip_count, MAX(timestamp) as last_seen
             FROM {$log_table}
             WHERE timestamp >= %d
             GROUP BY signature_hash
             HAVING ip_count >= %d",
                $start_time,
                $ip_threshold
            )
        );
        // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

        if (empty($suspicious_signatures)) {
            return;
        }

        $detected_signatures = [];

        foreach ($suspicious_signatures as $sig) {
            // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $is_already_flagged = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$signatures_table} WHERE signature_hash = %s", $sig->signature_hash));
            // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            if ($is_already_flagged) {
                continue;
            }

            // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $sample = $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT user_agent, request_uri, COUNT(*) as occurrence
                 FROM {$log_table} 
                 WHERE signature_hash = %s AND timestamp >= %d
                 GROUP BY user_agent, request_uri 
                 ORDER BY occurrence DESC 
                 LIMIT 1",
                    $sig->signature_hash,
                    $start_time
                )
            );
            // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

            if (!$sample) {
                $this->main_class->log_event(
                    'Signature analysis failed to retrieve a sample request for hash: ' . $sig->signature_hash,
                    'warning'
                );
                $user_agent_sample = 'N/A';
                $common_target = 'N/A';
            } else {
                $user_agent_sample = $sample->user_agent;
                $common_target = $sample->request_uri;
            }

            /* translators: %s is a placeholder */
            $reason = sprintf(__('Used by %1$d IPs. Common target: "%2$s"', 'advanced-ip-blocker'), $sig->ip_count, $common_target);

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            $wpdb->insert(
                $signatures_table,
                [
                    'signature_hash' => $sig->signature_hash,
                    'reason'         => $reason,
                    'first_seen'     => time(),
                    'last_seen'      => $sig->last_seen,
                    'expires_at'     => time() + $rule_ttl_seconds,
                ]
            );

            // 4. Log the event to the main security log
            $this->main_class->log_event(
                $reason,
                'critical',
                'signature_flagged',
                $sig->signature_hash,
                sprintf(
                    '{"signature_hash":"%s","user_agent":"%s","uri":"%s"}',
                    $sig->signature_hash,
                    addslashes($user_agent_sample),
                    addslashes($common_target)
                )
            );

            $detected_signatures[] = [
                'hash' => $sig->signature_hash,
                'reason' => $reason,
                'user_agent' => $user_agent_sample,
                'count' => $sig->ip_count,
                'target' => $common_target
            ];
        }

        if (!empty($detected_signatures)) {
            if (isset($this->main_class->notification_manager) && method_exists($this->main_class->notification_manager, 'send_signature_batch_notification')) {
                $this->main_class->notification_manager->send_signature_batch_notification($detected_signatures);
            }
        }
    }

    /**
    * Removes a specific signature from the malicious list.
    *
    * @param string $signature_hash The hash of the signature to remove.
    * @return bool True if successfully removed (or didn't exist), false on error.
    */
    public function delete_signature($signature_hash)
    {
        global $wpdb;
        $signatures_table = $wpdb->prefix . 'advaipbl_malicious_signatures';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $wpdb->delete(
            $signatures_table,
            ['signature_hash' => $signature_hash],
            ['%s']
        );

        return $result !== false;
    }

    /**
     * Gets details and evidence for a specific signature.
     *
     * @param string $signature_hash The hash of the signature to investigate.
     * @return array|false An array with details or false if not found.
     */
    public function get_signature_details($signature_hash)
    {
        global $wpdb;
        $log_table = $wpdb->prefix . 'advaipbl_request_log';

        // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $sample_request = $wpdb->get_row($wpdb->prepare(
            "SELECT user_agent, request_headers FROM {$log_table} WHERE signature_hash = %s LIMIT 1",
            $signature_hash
        ));
        // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

        if (!$sample_request) {
            return false;
        }

        // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $evidence = $wpdb->get_results($wpdb->prepare(
            "SELECT DISTINCT ip_hash, user_agent, request_uri, timestamp, is_fake_bot as is_impersonator 
             FROM {$log_table} 
             WHERE signature_hash = %s 
             ORDER BY timestamp DESC
             LIMIT 15",
            $signature_hash
        ));
        // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

        $details = [
            'sample_user_agent' => $sample_request->user_agent,
            'sample_headers'    => json_decode($sample_request->request_headers, true) ?: [],
            'evidence'          => $evidence,
        ];

        return $details;
    }
}
