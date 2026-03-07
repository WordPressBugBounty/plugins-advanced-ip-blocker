<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class ADVAIPBL_Fingerprint_Manager {
     
	 private $main_class;
	 
	 public function __construct(ADVAIPBL_Main $main_class) { 
        $this->main_class = $main_class;
    }
	 
    /**
     * Genera una "firma" (huella digital) única para la petición actual.
     * La firma se basa en una combinación de cabeceras y características de la petición.
     *
     * @return string El hash SHA256 que representa la firma de la petición.
     */
        public function generate_signature() {
        $signature_parts = [];

        // 1. User-Agent
        $signature_parts[] = $this->main_class->get_user_agent();

        // 2. Cabeceras de Aceptación (los bots simples a menudo no las envían o son genéricas)
        $signature_parts[] = isset($_SERVER['HTTP_ACCEPT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'])) : 'no-accept';
        $signature_parts[] = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'])) : 'no-language';
        $signature_parts[] = isset($_SERVER['HTTP_ACCEPT_ENCODING']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_ENCODING'])) : 'no-encoding';                
        $signature_string = implode('|', $signature_parts);

        return hash('sha256', $signature_string);
    }

    /**
     * Extrae las cabeceras relevantes de la petición para guardarlas en el log.
     *
     * @return string Un string JSON con las cabeceras.
     */
    public function get_request_headers_for_log() {
        $headers_to_log = [
            'Accept', 'Accept-Language', 'Accept-Encoding', 'Referer', 'Origin',
            'CF-Connecting-IP', 'X-Forwarded-For', 'X-Real-IP' // Cabeceras de proxy comunes
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
 * Analiza los logs de peticiones para encontrar y marcar firmas maliciosas.
 * Se ejecuta a través de un WP-Cron.
 *
 * @param int $ip_threshold          El número mínimo de IPs distintas para marcar una firma.
 * @param int $analysis_window_seconds El período de tiempo (hacia atrás) a analizar.
 * @param int $rule_ttl_seconds        El tiempo de vida (TTL) de una nueva regla de firma.
 */
public function analyze_and_flag_signatures($ip_threshold, $analysis_window_seconds, $rule_ttl_seconds) {
    global $wpdb;
    $log_table = $wpdb->prefix . 'advaipbl_request_log';
    $signatures_table = $wpdb->prefix . 'advaipbl_malicious_signatures';

    // Borramos las firmas que ya han expirado
    // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query($wpdb->prepare("DELETE FROM {$signatures_table} WHERE expires_at <= %d", time()));
    // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

    $start_time = time() - $analysis_window_seconds;

    // 1. Encontrar firmas sospechosas (usadas por múltiples IPs)
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
        // Comprobamos si esta firma ya está marcada como maliciosa (y no ha expirado)
        // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $is_already_flagged = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$signatures_table} WHERE signature_hash = %s", $sig->signature_hash));
        // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ($is_already_flagged) {
            continue;
        }

        // 2. Obtener un ejemplo de la petición más común para esta firma
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

        // Añadimos un log si la consulta de ejemplo falla, para depuración futura.
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

        /* translators: 1: Number of IPs, 2: The most common URL target. */
        $reason = sprintf(__('Used by %1$d IPs. Common target: "%2$s"', 'advanced-ip-blocker'), $sig->ip_count, $common_target);

        // 3. Marcar la firma como maliciosa
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
            $sig->signature_hash, // Use hash as IP identifier
            sprintf('{"signature_hash":"%s","user_agent":"%s","uri":"%s"}', 
                $sig->signature_hash, 
                addslashes($user_agent_sample), 
                addslashes($common_target)
            )
        );

        // 5. Add to batch list
        $detected_signatures[] = [
            'hash' => $sig->signature_hash,
            'reason' => $reason,
            'user_agent' => $user_agent_sample,
            'count' => $sig->ip_count,
            'target' => $common_target
        ];
    }

    // 6. Send batch notification if any
    if (!empty($detected_signatures)) {
        if (isset($this->main_class->notification_manager) && method_exists($this->main_class->notification_manager, 'send_signature_batch_notification')) {
            $this->main_class->notification_manager->send_signature_batch_notification($detected_signatures);
        }
    }
}
	
	 /**
     * Elimina una firma específica de la lista de maliciosos.
     *
     * @param string $signature_hash El hash de la firma a eliminar.
     * @return bool True si se eliminó con éxito (o no existía), false en caso de error.
     */
    public function delete_signature($signature_hash) {
        global $wpdb;
        $signatures_table = $wpdb->prefix . 'advaipbl_malicious_signatures';

        $result = $wpdb->delete(
            $signatures_table,
            ['signature_hash' => $signature_hash],
            ['%s']
        );
        
        // delete devuelve el número de filas eliminadas, o false en caso de error.
        return $result !== false;
    }
	
	    /**
     * Obtiene los detalles y la evidencia de una firma específica.
     *
     * @param string $signature_hash El hash de la firma a investigar.
     * @return array|false Un array con los detalles o false si no se encuentra.
     */
    public function get_signature_details($signature_hash) {
        global $wpdb;
        $log_table = $wpdb->prefix . 'advaipbl_request_log';

        // 1. Obtenemos una petición de ejemplo para desglosar la firma (cabeceras, etc.)
        // phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $sample_request = $wpdb->get_row($wpdb->prepare(
            "SELECT user_agent, request_headers FROM {$log_table} WHERE signature_hash = %s LIMIT 1",
            $signature_hash
        ));
        // phpcs:enable PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

        if (!$sample_request) {
            return false;
        }
        
        // 2. Obtenemos la evidencia: las últimas 15 IPs distintas que usaron esta firma.
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