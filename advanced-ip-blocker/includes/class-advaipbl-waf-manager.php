<?php
// /includes/class-advaipbl-waf-manager.php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class ADVAIPBL_Waf_Manager {

     /**
     * Escanea la petición actual contra las reglas WAF personalizadas del usuario,
     * respetando la lista de URLs excluidas.
     *
     * @return string|false La regla que ha coincidido, o false si no hay coincidencia.
     */
    public function run_waf_scan() {
		if (is_user_logged_in() && current_user_can('unfiltered_html')) {
        return false; // El usuario es un admin o editor, no se escanea.
    }
	    $main_class = ADVAIPBL_Main::get_instance();
        $request_uri = $main_class->get_current_request_uri();   
        // 1. Obtenemos las opciones del plugin una sola vez.
        // Hacemos esto aquí en lugar de en el constructor para asegurar que tenemos los datos más frescos.
        $options = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $raw_excluded_urls = $options['waf_excluded_urls'] ?? '';
    
        if (!empty(trim($raw_excluded_urls))) {
            $excluded_urls = array_filter(array_map('trim', explode("\n", $raw_excluded_urls)));
            
            // 2. Comprobamos si la URI actual contiene alguna de las cadenas de exclusión.
            if (!empty($excluded_urls)) {
                foreach ($excluded_urls as $excluded_url_fragment) {
                    // Ignoramos líneas vacías o de comentarios
                    if (empty($excluded_url_fragment) || strpos($excluded_url_fragment, '#') === 0) {
                        continue;
                    }
                    // Si encontramos una coincidencia (insensible a mayúsculas), terminamos la función inmediatamente.
                    if (stripos($request_uri, $excluded_url_fragment) !== false) {
                        return false; // URL excluida, no se escanea.
                    }
                }
            }
        }

        // Si es una petición XML-RPC, la ignoramos completamente aquí.
        if (strpos($request_uri, 'xmlrpc.php') !== false) {
            return false;
        }
    
        // El resto del escaneo para las reglas personalizadas continúa como antes.
        $raw_rules = get_option(ADVAIPBL_Main::OPTION_WAF_RULES, '');
        if (empty(trim($raw_rules))) {
            return false;
        }
    
        $rules = array_filter(array_map('trim', explode("\n", $raw_rules)));
        if (empty($rules)) {
            return false;
        }
    
        $request_data_to_scan = [
            // phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
            'GET'         => $_GET,
            'POST'        => $_POST,
            'COOKIE'      => $_COOKIE,
            // phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
            'REQUEST_URI' => $request_uri,
            'USER_AGENT'  => $main_class->get_user_agent(),
        ];
    
        foreach ($rules as $rule) {
            if (empty($rule) || strpos($rule, '#') === 0) {
                continue; // Ignoramos reglas vacías o comentadas
            }
            $pattern = '#' . $rule . '#i';
            if ($this->scan_data_recursively($request_data_to_scan, $pattern)) {
                return $rule; // ¡Amenaza detectada!
            }
        }
    
        return false;
    }

    /**
     * Escanea recursivamente datos buscando una coincidencia.
     * @param mixed  $data    Dato o array a escanear.
     * @param string $pattern Expresión regular.
     * @return bool True si hay coincidencia.
     */
    private function scan_data_recursively($data, $pattern) {
        if (is_array($data)) {
            foreach ($data as $value) {
                if ($this->scan_data_recursively($value, $pattern)) {
                    return true;
                }
            }
        } elseif (is_string($data)) {
            if (@preg_match($pattern, $data)) {
                return true;
            }
        }
        return false;
    }
}