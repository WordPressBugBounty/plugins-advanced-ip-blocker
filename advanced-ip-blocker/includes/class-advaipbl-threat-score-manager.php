<?php
// /includes/class-advaipbl-threat-score-manager.php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class ADVAIPBL_Threat_Score_Manager {

    /**
     * @var ADVAIPBL_Main La instancia de la clase principal del plugin.
     */
    private $main_class;

    /**
     * @var string El nombre de la tabla de puntuaciones en la base de datos.
     */
    private $table_name;

    /**
     * Constructor.
     *
     * @param ADVAIPBL_Main $main_class La instancia de la clase principal.
     */
    public function __construct(ADVAIPBL_Main $main_class) {
        global $wpdb;
        $this->main_class = $main_class;
        $this->table_name = $wpdb->prefix . 'advaipbl_ip_scores';
    }

        /**
     * Obtiene la puntuación de amenaza actual para una IP específica.
     *
     * @param string $ip La dirección IP a consultar.
     * @return int La puntuación actual. Devuelve 0 si la IP no está en la tabla.
     */
    public function get_score($ip) {
        global $wpdb;
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $score = $wpdb->get_var($wpdb->prepare(
            "SELECT score FROM {$this->table_name} WHERE ip = %s",
            $ip
        ));

        // get_var devuelve NULL si no encuentra nada. Nos aseguramos de devolver un entero.
        return (int) $score;
    }

    /**
     * Incrementa la puntuación de amenaza para una IP y registra el evento.
     * Si la IP no existe en la tabla, se crea una nueva entrada.
     *
     * @param string $ip La dirección IP cuya puntuación se incrementará.
     * @param int    $points_to_add El número de puntos a añadir.
     * @param string $event_type Una descripción breve del evento (ej. '404', 'WAF', 'Login Failure').
     * @param array  $details Detalles adicionales sobre el evento para el log (ej. URL, regla WAF).
     * @return int La nueva puntuación total de la IP después del incremento.
     */
    public function increment_score($ip, $points_to_add, $event_type, $details = []) {
        global $wpdb;
        
        // No añadimos puntos si el valor es cero o negativo.
        if ($points_to_add <= 0) {
            return $this->get_score($ip);
        }

        $current_timestamp = time();

        // Creamos la entrada del log para este evento específico.
        $new_log_entry = [
            'ts'      => $current_timestamp,
            'event'   => $event_type,
            'points'  => $points_to_add,
            'details' => $details,
        ];
        
        // Obtenemos el log existente para poder añadir la nueva entrada.
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $existing_log_json = $wpdb->get_var($wpdb->prepare(
            "SELECT log_details FROM {$this->table_name} WHERE ip = %s",
            $ip
        ));

        $log_history = json_decode((string) $existing_log_json, true);
        if (!is_array($log_history)) {
            $log_history = [];
        }

        // Añadimos la nueva entrada al principio del historial.
        array_unshift($log_history, $new_log_entry);

        // Limitamos el historial a los últimos 20 eventos para evitar que el campo crezca indefinidamente.
        if (count($log_history) > 20) {
            $log_history = array_slice($log_history, 0, 20);
        }

        $new_log_json = wp_json_encode($log_history);

        // Usamos una única consulta eficiente para insertar o actualizar.
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($wpdb->prepare(
            "INSERT INTO {$this->table_name} (ip, score, last_event_timestamp, log_details)
             VALUES (%s, %d, %d, %s)
             ON DUPLICATE KEY UPDATE 
                score = score + %d, 
                last_event_timestamp = %d,
                log_details = %s",
            $ip,                        // Para INSERT: ip
            $points_to_add,             // Para INSERT: score inicial
            $current_timestamp,         // Para INSERT: last_event_timestamp
            $new_log_json,              // Para INSERT: log_details
            $points_to_add,             // Para UPDATE: valor a sumar a score
            $current_timestamp,         // Para UPDATE: nuevo last_event_timestamp
            $new_log_json               // Para UPDATE: nuevo log_details
        ));
        
        // Devolvemos la puntuación actualizada.
        return $this->get_score($ip);
    }

     /**
     * Reduce la puntuación de las IPs que han estado inactivas durante un período.
     * Este método será llamado por un cron job.
     *
     * @param int $decay_points Puntos a restar.
     * @param int $inactive_for_seconds El tiempo en segundos de inactividad para que una IP sea elegible para el decaimiento.
     * @return array Un array con el número de filas actualizadas y eliminadas.
     */
    public function decay_scores($decay_points, $inactive_for_seconds) {
        global $wpdb;

        if ($decay_points <= 0 || $inactive_for_seconds <= 0) {
            return ['updated' => 0, 'deleted' => 0];
        }

        $current_timestamp = time();
        $threshold_timestamp = $current_timestamp - $inactive_for_seconds;

        // 1. Reducimos la puntuación de las IPs inactivas.
        // Usamos una consulta SQL para restar los puntos, asegurándonos de que nunca baje de 0.
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $updated = $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table_name}  
            SET score = GREATEST(0, score - %d) 
             WHERE last_event_timestamp < %d",
            $decay_points,
            $threshold_timestamp
        ));

        // 2. Eliminamos las filas cuya puntuación ha llegado a 0.
        // Esto mantiene la tabla limpia y eficiente.
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $deleted = $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE score <= 0"
        );

        return [
            'updated' => (int) $updated,
            'deleted' => (int) $deleted,
        ];
    }

     /**
     * Resetea la puntuación de una IP específica a 0.
     * En lugar de poner a 0, eliminamos la fila para mantener la tabla limpia.
     *
     * @param string $ip La dirección IP a resetear.
     * @return bool True si se eliminó con éxito o no existía, false en caso de error.
     */
    public function reset_score($ip) {
        global $wpdb;
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $wpdb->delete(
            $this->table_name,
            ['ip' => $ip],
            ['%s']
        );
        
        // delete devuelve el número de filas eliminadas, o false en error.
        return $result !== false;
    }
	
	    /**
     * Obtiene los detalles del log (historial de eventos) para una IP específica.
     *
     * @param string $ip La dirección IP a consultar.
     * @return array|false Un array con el historial de eventos o false si no se encuentra.
     */
    public function get_log_details($ip) {
        global $wpdb;
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $log_json = $wpdb->get_var($wpdb->prepare(
            "SELECT log_details FROM {$this->table_name} WHERE ip = %s",
            $ip
        ));

        // get_var devuelve NULL si no encuentra la fila.
        if ($log_json === null) {
            return false;
        }
        
        $log_details = json_decode($log_json, true);
        
        // Si el JSON está vacío o malformado, devolvemos un array vacío para evitar errores.
        return is_array($log_details) ? $log_details : [];
    }
}