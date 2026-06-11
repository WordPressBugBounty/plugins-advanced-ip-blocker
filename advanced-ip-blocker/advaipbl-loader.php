<?php
/**
 * Advanced IP Blocker - Edge Firewall Loader v6.2 (Stable)
 */

// Explicit check for direct access to satisfy Plugin Check while allowing auto_prepend_file.
if ( ! defined( 'ABSPATH' ) ) {
    $advaipbl_script_filename = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
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

// Cargar WordPress de forma nativa.
// Esto arranca todo el ecosistema y dispara el hook 'init',
// el cual carga automáticamente todas las defensas del plugin.
require_once ABSPATH . 'wp-config.php';

// Cargar el plugin forzosamente como medida de seguridad en caso 
// de que haya sido desactivado en la base de datos pero el Edge Firewall
// siga activo en el servidor (ej. auto_prepend_file).
require_once __DIR__ . '/advanced-ip-blocker.php';