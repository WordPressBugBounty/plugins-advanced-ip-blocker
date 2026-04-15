<?php
/**
 * Advanced IP Blocker - Edge Firewall Loader v6.2 (Stable)
 */

// Explicit check for direct access to satisfy Plugin Check while allowing auto_prepend_file.
if ( ! defined( 'ABSPATH' ) ) {
    $advaipbl_script_filename = isset($_SERVER['SCRIPT_FILENAME']) ? sanitize_text_field(wp_unslash($_SERVER['SCRIPT_FILENAME'])) : '';
    if ( basename( $advaipbl_script_filename ) === basename( __FILE__ ) ) {
        exit( 'Restricted access.' );
    }
}

if (defined('ADVAIPBL_LOADER_RUN')) { return; }
define('ADVAIPBL_LOADER_RUN', true);

// Si ABSPATH está definido, estamos en un flujo normal de WordPress.
// Este archivo NO debe ejecutar la lógica Edge.
// Su única función aquí es manejar la caché.
if (defined('ABSPATH')) {
    // La lógica de caché ahora está en `serve_js_challenge`, por lo que este archivo no necesita hacer nada
    // en un flujo normal de WordPress. Simplemente salimos.
    return;
}

// --- A partir de aquí, solo se ejecuta en modo standalone (Edge) ---

if (PHP_SAPI === 'cli') { return; }

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$wp_load_path = '';
$current_dir = __DIR__;
for ($i = 0; $i < 7; $i++) {
    if (file_exists($current_dir . '/wp-load.php')) {
        $wp_load_path = $current_dir . '/wp-load.php';
        break;
    }
    $current_dir = dirname($current_dir);
}
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
if (!$wp_load_path) { return; }

define('ABSPATH', dirname($wp_load_path) . '/');
define('ADVAIPBL_EDGE_MODE', true);

ob_start(); // Iniciar el buffer de salida para capturar Notices.

// Cargar lo mínimo de WP y luego el plugin completo.
require_once ABSPATH . 'wp-config.php';
require_once ABSPATH . 'wp-includes/class-wpdb.php';
require_once ABSPATH . 'wp-includes/plugin.php';
require_once ABSPATH . 'wp-includes/load.php';
require_once ABSPATH . 'wp-includes/option.php';
require_once ABSPATH . 'wp-includes/functions.php';
require_once ABSPATH . 'wp-includes/pluggable.php';

require_once __DIR__ . '/advanced-ip-blocker.php';

try {
    $advaipbl = ADVAIPBL_Main::get_instance();
    
    $advaipbl->js_challenge_manager->verify_submission();
    $advaipbl->is_visitor_asn_whitelisted();
    $advaipbl->verify_known_bots();
    $advaipbl->check_for_endpoint_lockdown();
    $advaipbl->check_for_malicious_signature();
    $advaipbl->check_for_geo_challenge();
    $advaipbl->run_all_block_checks();

} catch (Exception $e) { /* silent fail */ }