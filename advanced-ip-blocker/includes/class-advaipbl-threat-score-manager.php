<?php

if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Threat_Score_Manager
{
    /**
     * @var ADVAIPBL_Main The main plugin class instance.
     */
    private $main_class;

    /**
     * @var string The name of the scores table in the database.
     */
    private $table_name;

    /**
     * Constructor.
     *
     * @param ADVAIPBL_Main $main_class The main class instance.
     */
    public function __construct(ADVAIPBL_Main $main_class)
    {
        global $wpdb;
        $this->main_class = $main_class;
        $this->table_name = $wpdb->prefix . 'advaipbl_ip_scores';
    }

    /**
     * Gets the current threat score for a specific IP.
     *
     * @param string $ip The IP address to query.
     * @return int The current score. Returns 0 if IP is not in the table.
     */
    public function get_score($ip)
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $score = $wpdb->get_var($wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "SELECT score FROM " . $this->table_name . " WHERE ip = %s",
            $ip
        ));

        return (int) $score;
    }

    /**
     * Increments the threat score for an IP and logs the event.
     * If the IP doesn't exist in the table, a new entry is created.
     *
     * @param string $ip The IP address whose score will be incremented.
     * @param int    $points_to_add The number of points to add.
     * @param string $event_type A short event description (e.g. '404', 'WAF', 'Login Failure').
     * @param array  $details Additional event details for the log (e.g. URL, WAF rule).
     * @return int The new total IP score after incrementing.
     */
    public function increment_score($ip, $points_to_add, $event_type, $details = [])
    {
        global $wpdb;

        if ($points_to_add <= 0) {
            return $this->get_score($ip);
        }

        $current_timestamp = time();

        $new_log_entry = [
            'ts'      => $current_timestamp,
            'event'   => $event_type,
            'points'  => $points_to_add,
            'details' => $details,
        ];

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $existing_log_json = $wpdb->get_var($wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "SELECT log_details FROM " . $this->table_name . " WHERE ip = %s",
            $ip
        ));

        $log_history = json_decode((string) $existing_log_json, true);
        if (!is_array($log_history)) {
            $log_history = [];
        }

        array_unshift($log_history, $new_log_entry);

        if (count($log_history) > 20) {
            $log_history = array_slice($log_history, 0, 20);
        }

        $new_log_json = wp_json_encode($log_history);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "INSERT INTO " . $this->table_name . " (ip, score, last_event_timestamp, log_details)
             VALUES (%s, %d, %d, %s)
             ON DUPLICATE KEY UPDATE 
                score = score + %d, 
                last_event_timestamp = %d,
                log_details = %s",
            $ip,
            $points_to_add,
            $current_timestamp,
            $new_log_json,
            $points_to_add,
            $current_timestamp,
            $new_log_json
        ));

        return $this->get_score($ip);
    }

    /**
    * Reduces the score for IPs inactive during a period.
    * Called via cron job.
    *
    * @param int $decay_points Points to subtract.
    * @param int $inactive_for_seconds Inactive time in seconds for an IP to be eligible for decay.
    * @return array An array with the number of updated and deleted rows.
    */
    public function decay_scores($decay_points, $inactive_for_seconds)
    {
        global $wpdb;

        if ($decay_points <= 0 || $inactive_for_seconds <= 0) {
            return ['updated' => 0, 'deleted' => 0];
        }

        $current_timestamp = time();
        $threshold_timestamp = $current_timestamp - $inactive_for_seconds;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $updated = $wpdb->query($wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "UPDATE " . $this->table_name . "  
            SET score = GREATEST(0, score - %d) 
             WHERE last_event_timestamp < %d",
            $decay_points,
            $threshold_timestamp
        ));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $deleted = $wpdb->query(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "DELETE FROM " . $this->table_name . " WHERE score <= 0"
        );

        return [
            'updated' => (int) $updated,
            'deleted' => (int) $deleted,
        ];
    }

    /**
    * Resets a specific IP's score to 0.
    * We delete the row to keep the table clean instead of setting to 0.
    *
    * @param string $ip The IP address to reset.
    * @return bool True if successfully deleted or didn't exist, false on error.
    */
    public function reset_score($ip)
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $wpdb->delete(
            $this->table_name,
            ['ip' => $ip],
            ['%s']
        );

        return $result !== false;
    }

    /**
     * Gets the log details (event history) for a specific IP.
     *
     * @param string $ip The IP address to query.
     * @return array|false An array with the event history or false if not found.
     */
    public function get_log_details($ip)
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $log_json = $wpdb->get_var($wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "SELECT log_details FROM " . $this->table_name . " WHERE ip = %s",
            $ip
        ));

        if ($log_json === null) {
            return false;
        }

        $log_details = json_decode($log_json, true);

        return is_array($log_details) ? $log_details : [];
    }
}
