<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Reporter_Manager {

    private $plugin;
    
    // Tipos de reporte permitidos (Expandible en el futuro)
    private $allowed_types = [
    'abuseipdb', 
    'asn',
    'waf',       
    'login_lockdown', 
    'xmlrpc_block',
    'threat_score',
    'rate_limit',
    'aib_network',
    'impersonation',
];

    public function __construct( ADVAIPBL_Main $plugin_instance ) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Añade un evento a la cola de reportes pendientes.
     * 
     * @param string $ip La IP atacante.
     * @param string $type El tipo de bloqueo.
     * @param array $extra_data Datos de contexto (UA, URI, Score, etc).
     */
    public function queue_report( $ip, $type, $extra_data = [] ) {
        // Filtrado inicial: Solo reportamos tipos de interés para la red
        if ( ! in_array( $type, $this->allowed_types, true ) ) {
            return;
        }
        
        // Filtrado de privacidad: No reportar IPs privadas o locales
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_pending_reports';

        // Preparamos el contexto rico
        $context = [
            'ua' => $this->plugin->get_user_agent(),
            'uri' => $extra_data['uri'] ?? '',
            'method' => $this->plugin->get_request_method(),
            'score' => $extra_data['abuse_score'] ?? 0, // Si viene de AbuseIPDB
            'rule' => $extra_data['rule'] ?? '', // Si es WAF
        ];

        // Insertamos en la cola. 
        // Nota: No comprobamos duplicados estrictos para rendimiento. 
        // El servidor central hará la agregación (si una IP ataca 10 veces, queremos saberlo).
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table_name,
            [
                'ip' => $ip,
                'report_type' => $type,
                'timestamp' => time(),
                'context' => wp_json_encode($context)
            ]
        );
    }

    /**
     * Obtiene el lote de reportes para enviar y limpia la tabla.
     * Se llamará desde el Cron.
     *
     * @param int $limit Máximo de reportes por lote.
     * @return array Datos listos para enviar a la API.
     */
    public function get_batch_for_api( $limit = 50 ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_pending_reports';

        // Obtenemos los X más antiguos
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table_name} ORDER BY timestamp ASC LIMIT %d", $limit ), ARRAY_A );

        if ( empty( $rows ) ) {
            return [];
        }

        // Preparamos los IDs para borrarlos tras el envío (o antes, para evitar bucles si la API falla)
        // Estrategia "Fire and Forget" local: Borramos al leer para no saturar la DB local nunca.
        $ids_to_delete = wp_list_pluck( $rows, 'id' );
        if ( ! empty( $ids_to_delete ) ) {
            $ids_string = implode( ',', array_map( 'absint', $ids_to_delete ) );
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query( "DELETE FROM {$table_name} WHERE id IN ($ids_string)" );
        }

        // Formateamos para la API
        $payload = [
            'site_hash' => hash( 'sha256', home_url() ), // Identificador anónimo del sitio
            'version' => ADVAIPBL_VERSION,
            'reports' => []
        ];

        foreach ( $rows as $row ) {
            $payload['reports'][] = [
                'ip' => $row['ip'],
                'type' => $row['report_type'],
                'ts' => $row['timestamp'],
                'meta' => json_decode( $row['context'], true )
            ];
        }

        return $payload;
    }
}