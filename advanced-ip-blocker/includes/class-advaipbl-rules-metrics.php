<?php

if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Handles lightweight, asynchronous metrics gathering for Advanced Rules
 * to prevent database locking on high traffic sites.
 */
class ADVAIPBL_Rules_Metrics {

    const OPTION_METRICS = 'advaipbl_advanced_rules_metrics';
    const TRANSIENT_BUFFER = 'advaipbl_rules_buffer';
    const CRON_HOOK = 'advaipbl_aggregate_rules_metrics';

    private $plugin;
    
    /**
     * In-memory buffer for the current request.
     * Format: [ 'rule_id_1' => ['hits' => 2, 'passed' => 0], ... ]
     */
    private static $runtime_buffer = [];

    public function __construct(ADVAIPBL_Main $plugin_instance) {
        $this->plugin = $plugin_instance;

        // Register the shutdown function to save metrics at the end of the request
        add_action('shutdown', [$this, 'save_runtime_buffer']);

        // Hook the cron job for aggregation
        add_action(self::CRON_HOOK, [$this, 'aggregate_metrics']);
    }

    /**
     * Increments the hit or pass counter for a specific rule.
     * 
     * @param string $rule_id
     * @param string $type 'hits' or 'passed'
     */
    public function increment($rule_id, $type = 'hits') {
        if (!isset(self::$runtime_buffer[$rule_id])) {
            self::$runtime_buffer[$rule_id] = ['hits' => 0, 'passed' => 0];
        }
        
        if ($type === 'hits' || $type === 'passed') {
            self::$runtime_buffer[$rule_id][$type]++;
        }

        // Si hay Object Cache persistente (Redis/Memcached), podemos usarlo directamente.
        // Pero para simplificar, usamos el buffer de memoria y lo volcamos en shutdown.
    }

    /**
     * Called at the end of the PHP request to flush the runtime buffer.
     */
    public function save_runtime_buffer() {
        if (empty(self::$runtime_buffer)) {
            return;
        }

        // To avoid DB locking, we use a Transient to queue the metrics.
        // If the site has persistent Object Cache, this is very fast.
        // If not, it writes to the DB, but we only do it once per request,
        // and we could potentially add a lock to only do it every X seconds.
        
        // Fetch existing buffer
        $existing_buffer = get_transient(self::TRANSIENT_BUFFER);
        if (!is_array($existing_buffer)) {
            $existing_buffer = [];
        }

        // Merge runtime buffer into existing buffer
        foreach (self::$runtime_buffer as $rule_id => $counts) {
            if (!isset($existing_buffer[$rule_id])) {
                $existing_buffer[$rule_id] = ['hits' => 0, 'passed' => 0];
            }
            $existing_buffer[$rule_id]['hits'] += $counts['hits'];
            $existing_buffer[$rule_id]['passed'] += $counts['passed'];
        }

        // Save back to transient (expires in 1 day to prevent infinite buildup if cron fails)
        set_transient(self::TRANSIENT_BUFFER, $existing_buffer, DAY_IN_SECONDS);
    }

    /**
     * Cron job callback to aggregate the transient buffer into the permanent storage.
     */
    public function aggregate_metrics() {
        $buffer = get_transient(self::TRANSIENT_BUFFER);
        if (empty($buffer) || !is_array($buffer)) {
            return;
        }

        // Clear the transient immediately to prevent race conditions
        delete_transient(self::TRANSIENT_BUFFER);

        $metrics = get_option(self::OPTION_METRICS, []);
        if (!is_array($metrics)) {
            $metrics = [];
        }

        foreach ($buffer as $rule_id => $counts) {
            if (!isset($metrics[$rule_id])) {
                $metrics[$rule_id] = ['hits' => 0, 'passed' => 0];
            }
            $metrics[$rule_id]['hits'] += $counts['hits'];
            $metrics[$rule_id]['passed'] += $counts['passed'];
        }

        update_option(self::OPTION_METRICS, $metrics);
    }

    /**
     * Retrieves the aggregated metrics.
     * 
     * @return array
     */
    public function get_metrics() {
        return get_option(self::OPTION_METRICS, []);
    }

    /**
     * Gets metrics for a specific rule.
     * 
     * @param string $rule_id
     * @return array ['hits' => 0, 'passed' => 0]
     */
    public function get_rule_metrics($rule_id) {
        $metrics = $this->get_metrics();
        return $metrics[$rule_id] ?? ['hits' => 0, 'passed' => 0];
    }
}
