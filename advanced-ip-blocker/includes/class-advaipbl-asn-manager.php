<?php
// /includes/class-advaipbl-asn-manager.php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class ADVAIPBL_Asn_Manager {

    private $main_class;
    private $geolocation_manager;

    /**
     * Constructor.
     * @param ADVAIPBL_Main        $main_class  La instancia de la clase principal.
     * @param ADVAIPBL_geolocation_manager $geolocation_manager La instancia del gestor de APIs.
     */
    public function __construct(ADVAIPBL_Main $main_class, ADVAIPBL_Geolocation_Manager $geolocation_manager) {
        $this->main_class  = $main_class;
        $this->geolocation_manager = $geolocation_manager;
    }

     /**
     * Comprueba el ASN de una IP y, si está en una lista negra, devuelve los detalles del bloqueo.
     * @param string $ip La IP del visitante.
     * @return array|false Un array con los detalles del bloqueo o false si no hay coincidencia.
     */
    public function check_asn_block($ip) {
        $enable_manual_list = !empty($this->main_class->options['enable_manual_asn']);
        $enable_spamhaus_list = !empty($this->main_class->options['enable_spamhaus_asn']);

        if (!$enable_manual_list && !$enable_spamhaus_list) {
            return false;
        }

        $location_data = $this->geolocation_manager->fetch_location($ip);
        $visitor_asn = $this->extract_asn_from_data($location_data);

        if (!$visitor_asn) {
            return false;
        }

        // --- NEW: Check Whitelist First ---
        $whitelisted_asns = get_option(ADVAIPBL_Main::OPTION_WHITELISTED_ASNS, []);
        if (!empty($whitelisted_asns) && in_array($visitor_asn, $whitelisted_asns, true)) {
            // Explicitly allowed, so we skip any block checks.
            return false;
        }

        
        $is_blocked = false;
        $block_source = '';

        if ($enable_manual_list) {
            $blocked_asns_manual = get_option(ADVAIPBL_Main::OPTION_BLOCKED_ASNS, []);
            if (!empty($blocked_asns_manual) && in_array($visitor_asn, $blocked_asns_manual, true)) {
                $is_blocked = true;
                $block_source = 'Manual List';
            }
        }
        
        if (!$is_blocked && $enable_spamhaus_list) {
            $blocked_asns_spamhaus = get_option('advaipbl_spamhaus_asn_list', []);
            if (!empty($blocked_asns_spamhaus) && in_array($visitor_asn, $blocked_asns_spamhaus, true)) {
                $is_blocked = true;
                $block_source = 'Spamhaus';
            }
        }

        if ($is_blocked) {
            $asn_name = $location_data['as'] ?? ($location_data['asn']['name'] ?? '');
			/* translators: %1$s: AS number, %2$s: AS provider, %3$s: Spamhaus or manual list */
            $reason = sprintf(__('Blocked ASN: %1$s (%2$s) - Source: %3$s', 'advanced-ip-blocker'), $visitor_asn, $asn_name, $block_source);
            $log_data = [
                'asn_number' => $visitor_asn,
                'asn_name'   => $asn_name,
                'source'     => $block_source,
                'uri'        => $this->main_class->get_current_request_uri(),
            ];

            return ['reason_message' => $reason, 'log_data' => $log_data];
        }
        
        return false;
    }

    /**
     * Extrae el número de ASN (ej. "AS15169") de los datos devueltos por la API.
     * Es compatible con el formato de ip-api.com e ipinfo.io.
     * @param array|null $data Los datos de la API.
     * @return string|false El número de ASN o false si no se encuentra.
     */
    public function extract_asn_from_data($data) {
        if (empty($data) || !is_array($data)) {
            return false;
        }
        
        // Formato de ipinfo.io: $data['asn']['asn'] = "AS15169"
        if (isset($data['asn']['asn']) && preg_match('/^AS\d+$/i', $data['asn']['asn'])) {
            return strtoupper($data['asn']['asn']);
        }
        
        // Formato de ip-api.com: $data['as'] = "AS15169 Google LLC"
        if (isset($data['as'])) {
            preg_match('/(AS\d+)/i', $data['as'], $matches);
            if (!empty($matches[1])) {
                return strtoupper($matches[1]);
            }
        }

        return false;
    }
	
	    /**
     * Obtiene los detalles del log (historial de eventos) para una IP específica.
     *
     * @param string $ip La dirección IP a consultar.
     * @return array|false Un array con el historial de eventos o false si no se encuentra.
     */
    public function get_log_details($ip) {
        global $wpdb;
        
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $log_json = $wpdb->get_var($wpdb->prepare(
            "SELECT log_details FROM {$this->table_name} WHERE ip = %s",
            $ip
        ));
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

        if ($log_json === null) {
            return false;
        }
        
        $log_details = json_decode($log_json, true);
        
        return is_array($log_details) ? $log_details : [];
    }
}