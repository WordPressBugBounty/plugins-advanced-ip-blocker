<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class ADVAIPBL_Dashboard_Manager {

    private $main_class;
    private $session_manager;

    /**
     * Constructor modificado para aceptar la clase principal y el gestor de sesiones.
     * @param ADVAIPBL_Main $main_class
     * @param ADVAIPBL_User_Session_Manager $session_manager
     */
    public function __construct(ADVAIPBL_Main $main_class, ADVAIPBL_User_Session_Manager $session_manager) {
        $this->main_class = $main_class;
        $this->session_manager = $session_manager;
    }

    /**
     * Recopila todas las estadísticas para el dashboard en un solo array.
     * @return array
     */
    public function get_dashboard_stats() {
    $this->main_class->limpiar_ips_expiradas();

    $days = 7;
    $date_after = gmdate('Y-m-d H:i:s', strtotime("-{$days} days"));

    // Obtenemos los datos de los ataques para el mapa una sola vez.
    $live_attacks_data = $this->get_recent_attacks_for_map();

    return [
        'summary'            => $this->get_summary_stats($date_after),
        'timeline'           => $this->get_timeline_stats($days, $date_after),
        'top_ips'            => $this->get_top_attackers($date_after),
        'top_countries'      => $this->get_top_countries($date_after),
        'system_status'      => $this->get_system_status(),
        'live_attacks'       => $live_attacks_data,

        // Añadimos el contador de IPs bloqueadas activas.
        'blocked_ips_count'  => count($live_attacks_data),

    ];
}

    /**
     * Obtiene estadísticas de resumen: total de bloqueos y desglose por tipo.
     * @param string $date_after Fecha desde la cual contar (formato Y-m-d H:i:s).
     * @return array
     */
    private function get_summary_stats($date_after) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        
        $results = $wpdb->get_results(
    $wpdb->prepare(
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        "SELECT log_type, COUNT(*) as count
         FROM {$table_name}
         WHERE level IN ('critical', 'warning') AND log_type != 'general' AND timestamp >= %s
         GROUP BY log_type
         ORDER BY count DESC",
         // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $date_after
    ),
    ARRAY_A
);
        
        $stats = ['total' => 0, 'by_type' => []];
        if ($results) {
            foreach ($results as $row) {
                $stats['total'] += $row['count'];
                $stats['by_type'][$row['log_type']] = $row['count'];
            }
        }
        return $stats;
    }

    /**
     * Obtiene datos para el gráfico de línea de tiempo.
     * @param int    $days Número de días hacia atrás a consultar.
     * @param string $date_after Fecha desde la cual contar.
     * @return array
     */
    private function get_timeline_stats($days, $date_after) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        
        $results = $wpdb->get_results(
    $wpdb->prepare(
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        "SELECT DATE(timestamp) as day, COUNT(*) as count
         FROM {$table_name}
         WHERE level IN ('critical', 'warning') AND log_type != 'general' AND timestamp >= %s
         GROUP BY day
         ORDER BY day ASC",
         // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $date_after
    ),
    ARRAY_A
);

        // Rellenar los días sin eventos para un gráfico continuo.
        $timeline = [];
        for ($i = ($days - 1); $i >= 0; $i--) {
            $day_key = gmdate('Y-m-d', strtotime("-{$i} days"));
            $timeline[$day_key] = 0;
        }

        if ($results) {
            foreach ($results as $row) {
                if (isset($timeline[$row['day']])) {
                    $timeline[$row['day']] = (int) $row['count'];
                }
            }
        }
        return $timeline;
    }

    /**
     * Obtiene las 8 IPs más atacantes.
     * @param string $date_after Fecha desde la cual contar.
     * @return array
     */
    private function get_top_attackers($date_after) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        
        return $wpdb->get_results(
    $wpdb->prepare(
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        "SELECT ip, COUNT(*) as count
         FROM {$table_name}
         WHERE level IN ('critical', 'warning') AND log_type != 'general' AND ip NOT IN ('127.0.0.1', '::1') AND timestamp >= %s
         GROUP BY ip
         ORDER BY count DESC
         LIMIT 8",
         // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $date_after
    ),
    ARRAY_A
);
    }

    /**
     * Obtiene los 8 países más bloqueados de TODOS los tipos de bloqueo.
     * @param string $date_after Fecha desde la cual contar.
     * @return array
     */
    private function get_top_countries($date_after) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        
        return $wpdb->get_results(
    $wpdb->prepare(
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        "SELECT JSON_UNQUOTE(JSON_EXTRACT(details, '$.country')) as country, 
                JSON_UNQUOTE(JSON_EXTRACT(details, '$.country_code')) as country_code, 
                COUNT(*) as count
         FROM {$table_name}
         WHERE level IN ('critical', 'warning')
           AND log_type != 'general'
           AND timestamp >= %s 
           AND JSON_UNQUOTE(JSON_EXTRACT(details, '$.country_code')) IS NOT NULL
         GROUP BY country_code, country
         ORDER BY count DESC
         LIMIT 8",
         // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $date_after
    ),
    ARRAY_A
);
    }

    /**
     * Obtiene estadísticas específicas de la protección de Spamhaus.
     * @return array
     */
    public function get_spamhaus_stats() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        $date_after = gmdate('Y-m-d H:i:s', strtotime("-7 days"));

        $spamhaus_asns = get_option('advaipbl_spamhaus_asn_list', []);
        
        $blocked_count = $wpdb->get_var(
    $wpdb->prepare(
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        "SELECT COUNT(DISTINCT ip)
         FROM {$table_name}
         WHERE log_type = 'asn'
           AND details LIKE %s
           AND timestamp >= %s",
           // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        '%"source":"Spamhaus"%',
        $date_after
    )
);

        return [
            'list_count'    => count($spamhaus_asns),
            'blocked_count' => (int) $blocked_count,
        ];
    }
 
        /**
     * Devuelve el estado de cada módulo de protección.
     * @return array
     */
    public function get_system_status() {
        $options = $this->main_class->options;
        return [
            'waf'              => !empty($options['enable_waf']),
            'rate_limit'       => !empty($options['rate_limiting_enable']),
            'geoblock'         => !empty($options['enable_geoblocking']),
            'honeypot'         => !empty($options['enable_honeypot_blocking']),
            'user_agent'       => !empty($options['enable_user_agent_blocking']),
            '404_blocking'     => true,
            '403_blocking'     => true,
            'login_blocking'   => true,
            'xmlrpc_mode'      => $options['xmlrpc_protection_mode'] ?? 'smart',
            // Separamos la protección ASN en sus dos componentes.
            'spamhaus_asn'     => !empty($options['enable_spamhaus_asn']),
            'manual_asn'       => !empty($options['enable_manual_asn']),
			'threat_scoring'   => !empty($options['enable_threat_scoring']),
			'signature_logging'   => !empty($options['enable_signature_engine']),
            'signature_analysis'  => !empty($options['enable_signature_analysis']),
            'signature_blocking'  => !empty($options['enable_signature_blocking']),
			'enable_2fa'  => !empty($options['enable_2fa']),
			'xmlrpc_lockdown'  => !empty($options['enable_xmlrpc_lockdown']),
			'login_lockdown'  => !empty($options['enable_login_lockdown']),
            '404_lockdown'  => !empty($options['enable_404_lockdown']),
            '403_lockdown'  => !empty($options['enable_403_lockdown']),
			'bot_verification'   => !empty($options['enable_bot_verification']),
            'geo_challenge'      => !empty($options['enable_geo_challenge']),
            'abuseipdb'          => !empty($options['enable_abuseipdb']),
            'activity_audit'     => !empty($options['enable_audit_log']),
            'advanced_rule'      => !empty($this->main_class->rules_engine->get_rules()),
			'htaccess_firewall'  => !empty($options['enable_htaccess_write']),
			'cloudflare_sync'    => !empty($options['enable_cloudflare']),
			'community_network'  => !empty($options['enable_community_blocking']),
        ];
    }

        /**
     * Obtiene los datos de geolocalización y los detalles del bloqueo (tipo, duración)
     * de las IPs actualmente bloqueadas para el mapa.
     *
     * @return array Un array de ataques con todos los datos necesarios para el popup.
     */
        public function get_recent_attacks_for_map() {
        $all_blocked_entries = $this->main_class->get_all_blocked_entries();

        if (empty($all_blocked_entries)) {
            return [];
        }

        $ips_to_locate = [];
        foreach ($all_blocked_entries as $entry) {
            $ip = $entry['ip'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips_to_locate[] = $ip;
            }
        }
        $ips_to_locate = array_unique($ips_to_locate);

        if (empty($ips_to_locate)) {
            return [];
        }
        
        $locations = $this->session_manager->get_cached_locations($ips_to_locate);

        $attacks_for_map = [];
        $options = $this->main_class->options;

        $entry_map = [];
        foreach ($all_blocked_entries as $entry) {
            if (filter_var($entry['ip'], FILTER_VALIDATE_IP)) {
                $entry_map[$entry['ip']] = $entry;
            }
        }

        foreach ($locations as $ip => $location_data) {
            if (isset($location_data['lat']) && isset($location_data['lon']) && isset($entry_map[$ip])) {
                
                $entry = $entry_map[$ip];
                $type = $entry['type'];
                $type_display = ($type === 'threat_score') ? $entry['detail'] : $entry['type_label'];

                $duration_minutes = (int) ($options['duration_' . $type] ?? 1440);
                $duration_text = '';
                if ($type === 'manual' || $duration_minutes <= 0) {
                    $duration_text = __('Permanent', 'advanced-ip-blocker');
                } else {
					/* translators: %d: The number of minutes. */
                    $duration_text = sprintf(__('%d minutes', 'advanced-ip-blocker'), $duration_minutes);
                }

                $attacks_for_map[] = [
                    'ip'            => $ip,
                    'lat'           => $location_data['lat'],
                    'lon'           => $location_data['lon'],
                    'country'       => $location_data['country'] ?? 'Unknown',
                    'city'          => $location_data['city'] ?? 'Unknown',
                    'type_label'    => $entry['type_label'],
                    'type_display'  => $type_display,
                    'duration_text' => $duration_text,
                ];
            }
        }

        $limit = 200; 
        return array_slice($attacks_for_map, 0, $limit);
    }

}