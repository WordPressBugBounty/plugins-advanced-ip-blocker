<?php

if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Class ADVAIPBL_Cache_Manager
 * 
 * Handles all custom database caching operations.
 * extracted from ADVAIPBL_Main to improve modularity.
 */
class ADVAIPBL_Cache_Manager {

    private $db_table;

    public function __construct() {
        global $wpdb;
        $this->db_table = $wpdb->prefix . 'advaipbl_cache';
    }

    /**
     * Retrieves a value from the custom cache table.
     * 
     * @param string $key             The cache key.
     * @param bool   $get_full_object Whether to return the full row object (including expiry).
     * @return mixed The cached value, or false if not found/expired.
     */
    public function get( $key, $get_full_object = false ) {
        global $wpdb;

        // Validar que la tabla existe (simple prevención)
        if ( ! $this->db_table ) {
            return false;
        }

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $query = $wpdb->prepare( 
            "SELECT cache_value, expires_at FROM {$this->db_table} WHERE cache_key = %s", 
            $key 
        );
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $row = $wpdb->get_row( $query, ARRAY_A );

        if ( ! $row ) {
            return false;
        }

        // Verificar caducidad
        if ( time() > $row['expires_at'] ) {
            // Opcional: Borrar si está caducado (lazy cleanup)
            $this->delete($key);
            return false;
        }

        $value = maybe_unserialize( $row['cache_value'] );

        if ( $get_full_object ) {
            return [
                'value'      => $value,
                'expires_at' => $row['expires_at']
            ];
        }

        return $value;
    }

    /**
     * Saves a value to the custom cache table.
     * 
     * @param string $key        The cache key.
     * @param mixed  $value      The value to store (will be serialized).
     * @param int    $expiration TTL in seconds.
     * @return int|false Number of rows affected or false on error.
     */
    public function set( $key, $value, $expiration ) {
        global $wpdb;

        $serialized_value = maybe_serialize( $value );
        $expires_at = time() + $expiration;

        // Usamos REPLACE INTO para manejar inserts y updates atómicos
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        // Usamos REPLACE INTO para manejar inserts y updates atómicos.
        // Suppress errors to avoid "Deadlock found" in logs under high concurrency.
        $wpdb->suppress_errors();
        $result = $wpdb->query( $wpdb->prepare( 
            "REPLACE INTO {$this->db_table} (cache_key, cache_value, expires_at) VALUES (%s, %s, %d)", 
            $key, 
            $serialized_value, 
            $expires_at 
        ) );
        $wpdb->show_errors();
        
        return $result;
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    }

    /**
     * Deletes a specific cache key.
     * 
     * @param string $key The cache key.
     * @return int|false Number of rows affected.
     */
    public function delete( $key ) {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $wpdb->delete( $this->db_table, ['cache_key' => $key] );
    }

    /**
     * Cleans up all expired entries.
     * Should be called via Cron.
     * 
     * @return int|false Number of rows deleted.
     */
    public function cleanup_expired() {
        global $wpdb;
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->suppress_errors();
        $result = $wpdb->query( $wpdb->prepare( 
            "DELETE FROM {$this->db_table} WHERE expires_at < %d", 
            time() 
        ) );
        $wpdb->show_errors();
        
        return $result;
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    }
}
