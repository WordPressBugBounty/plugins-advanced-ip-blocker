<?php
/**
 * Advanced IP Blocker - Edge Firewall Loader v6.2 (Stable)
 */


if ( ! defined( 'ABSPATH' ) ) {
    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    $advaipbl_script_filename = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
    if ( basename( $advaipbl_script_filename ) === basename( __FILE__ ) ) {
        exit( 'Restricted access.' );
    }
}

if (defined('ADVAIPBL_LOADER_RUN')) { return; }
define('ADVAIPBL_LOADER_RUN', true);




if (defined('ABSPATH')) {
    
    
    return;
}



if (PHP_SAPI === 'cli') { return; }


// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$wp_load_path = '';
// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$current_dir = __DIR__;
// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
for ($i = 0; $i < 7; $i++) {
    if (file_exists($current_dir . '/wp-load.php')) {
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        $wp_load_path = $current_dir . '/wp-load.php';
        break;
    }
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    $current_dir = dirname($current_dir);
}

if (!$wp_load_path) { return; }

define('ABSPATH', dirname($wp_load_path) . '/');
define('ADVAIPBL_EDGE_MODE', true);

ob_start(); 


// Esto arranca todo el ecosistema y dispara el hook 'init',

require_once ABSPATH . 'wp-config.php';




require_once __DIR__ . '/advanced-ip-blocker.php';