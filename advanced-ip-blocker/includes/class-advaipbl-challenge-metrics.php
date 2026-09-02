<?php

if (! defined('ABSPATH')) {
    exit;
}

/**
 * ADVAIPBL_Challenge_Metrics
 *
 * Tracks "Served", "Passed", and "Failed" challenges using an asynchronous memory buffer
 * that flushes to a transient at shutdown, avoiding database write-locks during high traffic.
 */
class ADVAIPBL_Challenge_Metrics
{
    public const TRANSIENT_KEY = 'advaipbl_challenge_buffer';
    public const OPTION_KEY = 'advaipbl_challenge_stats';
    public const CRON_HOOK = 'advaipbl_aggregate_challenge_metrics';

    private $plugin;

    private static $runtime_buffer = [
        'served' => 0,
        'passed' => 0,
        'failed' => 0
    ];

    private static $needs_flush = false;

    public function __construct($plugin)
    {
        $this->plugin = $plugin;

        add_action(self::CRON_HOOK, [$this, 'aggregate_metrics']);

        add_action('shutdown', [$this, 'flush_to_transient']);
    }

    /**
     * Increment a specific metric type: 'served', 'passed', or 'failed'
     *
     * @param string $type
     */
    public function increment($type)
    {
        if (isset(self::$runtime_buffer[$type])) {
            self::$runtime_buffer[$type]++;
            self::$needs_flush = true;
        }
    }

    /**
     * Flushes the current in-memory buffer to a transient.
     * This is called on PHP shutdown.
     */
    public function flush_to_transient()
    {
        if (!self::$needs_flush) {
            return;
        }

        $total = array_sum(self::$runtime_buffer);
        if ($total === 0) {
            return;
        }

        $transient_data = get_transient(self::TRANSIENT_KEY);
        if (!is_array($transient_data)) {
            $transient_data = [
                'served' => 0,
                'passed' => 0,
                'failed' => 0
            ];
        }

        foreach (self::$runtime_buffer as $key => $count) {
            $transient_data[$key] += $count;
        }

        set_transient(self::TRANSIENT_KEY, $transient_data, 12 * HOUR_IN_SECONDS);

        self::$needs_flush = false;
        self::$runtime_buffer = ['served' => 0, 'passed' => 0, 'failed' => 0];
    }

    /**
     * Aggregates transient data into permanent DB storage.
     * Called via WP-Cron hourly.
     */
    public function aggregate_metrics()
    {
        $transient_data = get_transient(self::TRANSIENT_KEY);

        if (is_array($transient_data)) {
            $today = gmdate('Y-m-d');
            $historical_data = get_option(self::OPTION_KEY, []);

            if (!is_array($historical_data)) {
                $historical_data = [];
            }

            if (!isset($historical_data[$today])) {
                $historical_data[$today] = [
                    'served' => 0,
                    'passed' => 0,
                    'failed' => 0
                ];
            }

            foreach (['served', 'passed', 'failed'] as $key) {
                if (isset($transient_data[$key])) {
                    $historical_data[$today][$key] += $transient_data[$key];
                }
            }

            $retention_days = (int) ($this->plugin->options['log_retention_days'] ?? 30);
            if ($retention_days < 1) {
                $retention_days = 30;
            }

            $cutoff_date = gmdate('Y-m-d', strtotime("-{$retention_days} days"));

            foreach ($historical_data as $date => $data) {
                if ($date < $cutoff_date) {
                    unset($historical_data[$date]);
                }
            }

            update_option(self::OPTION_KEY, $historical_data, false);

            delete_transient(self::TRANSIENT_KEY);
        }
    }

    /**
     * Gets all historical data for the dashboard charts.
     *
     * @return array
     */
    public function get_historical_stats()
    {
        $historical_data = get_option(self::OPTION_KEY, []);
        if (!is_array($historical_data)) {
            $historical_data = [];
        }

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

        ksort($historical_data);

        return $historical_data;
    }
}
