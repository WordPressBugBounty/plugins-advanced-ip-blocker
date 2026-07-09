<?php

if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Rate_Limiting_Manager {

    private $main_class;

    public function __construct(ADVAIPBL_Main $main_class) {
        $this->main_class = $main_class;
    }

    public function check_request_rate() {
        if (empty($this->main_class->options['rate_limiting_enable']) || (defined('WP_CLI') && WP_CLI) || current_user_can('manage_options')) {
            return;
        }

        // Global URL Exclusion Bypass
        if (method_exists($this->main_class, 'is_request_uri_excluded') && $this->main_class->is_request_uri_excluded()) {
            return;
        }

        $ip = $this->main_class->get_client_ip();

        // Si la IP ya está bloqueada por cualquier otro motivo, detenemos la ejecución inmediatamente.
        if ($this->main_class->is_ip_actively_blocked($ip)) {
            return;
        }

        if ($this->main_class->is_whitelisted($ip)) {
            return;
        }

        if (!empty($this->main_class->request_is_asn_whitelisted) || !empty($this->main_class->is_advanced_rule_allowed)) {
            return;
        }
        
        $options = $this->main_class->options;
        $current_uri = $this->main_class->get_current_request_uri();
        
        // 1. Process Advanced Rules
        $advanced_rules_json = $options['rate_limiting_advanced_rules'] ?? '[]';
        $advanced_rules = json_decode($advanced_rules_json, true);
        $matched_rule = null;

        if (is_array($advanced_rules)) {
            foreach ($advanced_rules as $rule) {
                if (empty($rule['endpoint'])) continue;
                if (strpos($current_uri, $rule['endpoint']) !== false) {
                    $matched_rule = $rule;
                    break; // First match wins
                }
            }
        }

        if ($matched_rule) {
            $limit = (int) $matched_rule['limit'];
            $window = (int) $matched_rule['window'];
            $action = $matched_rule['action'] ?? '429';
            $cache_prefix = 'advaipbl_rl_' . md5($matched_rule['endpoint']) . '_';
            $rule_name = $matched_rule['endpoint'];
        } else {
            // Fallback to Global Rule
            $limit  = (int) ($options['rate_limiting_limit'] ?? 120);
            $window = (int) ($options['rate_limiting_window'] ?? 60);
            $action = '403'; // Legacy global behavior
            $cache_prefix = 'advaipbl_rl_global_';
            $rule_name = 'Global';
        }

        if ($limit <= 0 || $window <= 0) {
            return;
        }

        $cache_key = $cache_prefix . $ip;
        $rate_data = $this->main_class->get_from_custom_cache($cache_key);
        $current_time = time();

        $request_count = 1;
        $first_request_time = $current_time;

        if ( is_array($rate_data) && isset($rate_data['first_request_time']) && ($current_time <= ($rate_data['first_request_time'] + $window)) ) {
            $request_count = (int)$rate_data['count'] + 1;
            $first_request_time = (int)$rate_data['first_request_time'];
        }

        $this->main_class->set_in_custom_cache($cache_key, ['count' => $request_count, 'first_request_time' => $first_request_time], $window + 10);

        if ($request_count > $limit) {
			/* translators: %1$d: request number, %2$d: seconds, %3$s: rule name */
            $reason = sprintf(__('Rate limit exceeded (%3$s): %1$d requests in %2$d seconds', 'advanced-ip-blocker'), $request_count, $window, $rule_name);
            $log_data = [ 
                'limit'   => $limit, 
                'window'  => $window, 
                'count'   => $request_count, 
                'uri'     => $current_uri,
                'action'  => $action
            ];
            
            // Log as warning for 429, critical for 403 block. For challenge, we log it below as info.
            if (strpos($action, 'challenge') !== 0) {
                $log_level = ($action === '403') ? 'critical' : 'warning';
                $this->main_class->log_specific_error('rate_limit', $ip, $log_data, $log_level);
            }
            
            if ($action === '403') {
                $this->main_class->block_ip_instantly($ip, 'rate_limit', $reason, $log_data);
            } elseif (strpos($action, 'challenge') === 0) {
                $this->main_class->log_specific_error('rate_limit_challenge', $ip, $log_data, 'info');
                
                if (isset($this->main_class->js_challenge_manager)) {
                    if (!$this->main_class->js_challenge_manager->is_vip_pass_valid()) {
                        $mode = str_replace('challenge_', '', $action);
                        if ($mode === 'managed') $mode = 'js_managed';
                        if ($mode === 'automatic') $mode = 'js_automatic';
                        $this->main_class->js_challenge_manager->serve_challenge('rate_limit', $mode);
                        exit;
                    }
                } else {
                    $this->serve_429_response();
                }
            } else {
                // Default is 429
                $this->serve_429_response();
            }
        }
    }
    
    private function serve_429_response() {
        if (!headers_sent()) {
            header('HTTP/1.1 429 Too Many Requests', true, 429);
            header('Retry-After: 60');
            header('Content-Type: text/html; charset=utf-8');
        }
        echo '<!DOCTYPE html><html><head><title>429 Too Many Requests</title></head><body style="font-family: sans-serif; padding: 2rem;">';
        echo '<h1>429 Too Many Requests</h1>';
        echo '<p>' . esc_html__('You have sent too many requests in a given amount of time. Please slow down.', 'advanced-ip-blocker') . '</p>';
        echo '</body></html>';
        exit;
    }
}