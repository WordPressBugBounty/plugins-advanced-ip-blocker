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
        
        $options = $this->main_class->options;
        $limit  = (int) ($options['rate_limiting_limit'] ?? 120);
        $window = (int) ($options['rate_limiting_window'] ?? 60);
        if ($limit <= 0 || $window <= 0) {
            return;
        }

        $cache_key = 'advaipbl_rl_' . $ip;
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
			/* translators: %1$d: request number, %2$d: seconds */
            $reason = sprintf(__('Rate limit exceeded: %1$d requests in %2$d seconds', 'advanced-ip-blocker'), $request_count, $window);
            $log_data = [ 
                'limit'   => $limit, 
                'window'  => $window, 
                'count'   => $request_count, 
                'uri'     => $this->main_class->get_current_request_uri(),
            ];
            
            // 1. Registramos el evento de bloqueo como 'critical' ANTES de bloquear.
            $this->main_class->log_specific_error('rate_limit', $ip, $log_data, 'critical');
            
            // 2. Llamamos a la función de bloqueo, que se encarga de las notificaciones y de detener el script.
            $this->main_class->block_ip_instantly($ip, 'rate_limit', $reason, $log_data);
        }
    }
}