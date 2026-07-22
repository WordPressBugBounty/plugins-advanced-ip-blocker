<?php

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * ADVAIPBL_Challenge_Metrics
 *
 * Tracks "Served", "Passed", and "Failed" challenges using an asynchronous memory buffer
 * that flushes to a transient at shutdown, avoiding database write-locks during high traffic.
 */
class ADVAIPBL_Challenge_Metrics {
    
    const TRANSIENT_KEY = 'advaipbl_challenge_buffer';
    const OPTION_KEY = 'advaipbl_challenge_stats';
    const CRON_HOOK = 'advaipbl_aggregate_challenge_metrics';

    private $plugin;

    // Buffer for the current PHP request
    private static $runtime_buffer = [
        'served' => 0,
        'passed' => 0,
        'failed' => 0
    ];

    private static $needs_flush = false;

    public function __construct( $plugin ) {
        $this->plugin = $plugin;

        // Register cron aggregation hook
        add_action(self::CRON_HOOK, [$this, 'aggregate_metrics']);
        
        // Register shutdown function to flush stats without blocking response
        add_action('shutdown', [$this, 'flush_to_transient']);
    }

    /**
     * Increment a specific metric type: 'served', 'passed', or 'failed'
     *
     * @param string $type
     */
    public function increment( $type ) {
        if (isset(self::$runtime_buffer[$type])) {
            self::$runtime_buffer[$type]++;
            self::$needs_flush = true;
        }
    }

    /**
     * Flushes the current in-memory buffer to a transient.
     * This is called on PHP shutdown.
     */
    public function flush_to_transient() {
        if (!self::$needs_flush) {
            return;
        }

        // Check if there's actually anything to flush
        $total = array_sum(self::$runtime_buffer);
        if ($total === 0) {
            return;
        }

        // Get existing transient data
        $transient_data = get_transient(self::TRANSIENT_KEY);
        if (!is_array($transient_data)) {
            $transient_data = [
                'served' => 0,
                'passed' => 0,
                'failed' => 0
            ];
        }

        // Add buffer to transient data
        foreach (self::$runtime_buffer as $key => $count) {
            $transient_data[$key] += $count;
        }

        // Save back to transient (expires in 12 hours as a failsafe)
        set_transient(self::TRANSIENT_KEY, $transient_data, 12 * HOUR_IN_SECONDS);

        // Reset buffer
        self::$needs_flush = false;
        self::$runtime_buffer = ['served' => 0, 'passed' => 0, 'failed' => 0];
    }

    /**
     * Aggregates transient data into permanent DB storage.
     * Called via WP-Cron hourly.
     */
    public function aggregate_metrics() {
        $transient_data = get_transient(self::TRANSIENT_KEY);
        
        if (is_array($transient_data)) {
            $today = gmdate('Y-m-d');
            $historical_data = get_option(self::OPTION_KEY, []);
            
            if (!is_array($historical_data)) {
                $historical_data = [];
            }

            // Initialize today's entry if it doesn't exist
            if (!isset($historical_data[$today])) {
                $historical_data[$today] = [
                    'served' => 0,
                    'passed' => 0,
                    'failed' => 0
                ];
            }

            // Add transient counts to today's history
            foreach (['served', 'passed', 'failed'] as $key) {
                if (isset($transient_data[$key])) {
                    $historical_data[$today][$key] += $transient_data[$key];
                }
            }

            // Prune old entries based on log retention settings
            $retention_days = (int) ($this->plugin->options['log_retention_days'] ?? 30);
            if ($retention_days < 1) $retention_days = 30; // Failsafe
            
            $cutoff_date = gmdate('Y-m-d', strtotime("-{$retention_days} days"));

            foreach ($historical_data as $date => $data) {
                if ($date < $cutoff_date) {
                    unset($historical_data[$date]);
                }
            }

            // Save permanent option
            update_option(self::OPTION_KEY, $historical_data, false);
            
            // Delete the transient as it has been aggregated
            delete_transient(self::TRANSIENT_KEY);
        }
    }

    /**
     * Gets all historical data for the dashboard charts.
     *
     * @return array
     */
    public function get_historical_stats() {
        $historical_data = get_option(self::OPTION_KEY, []);
        if (!is_array($historical_data)) {
            $historical_data = [];
        }
        
        // Also add the transient data to today's stats for "real-time" accuracy
        $transient_data = get_transient(self::TRANSIENT_KEY);
        if (is_array($transient_data)) {
            $today = gmdate('Y-m-d');
            if (!isset($historical_data[$today])) {
                $historical_data[$today] = ['served' => 0, 'passed' => 0, 'failed' => 0];
            }
            foreach (['served', 'passed', 'failed'] as $key) {
                if (isset($transient_data[$key])) {
                    $historical_data[$today][$key] += $transient_data[$key];
                }
            }
        }
        
        // Sort by date (ascending)
        ksort($historical_data);

        return $historical_data;
    }
}
