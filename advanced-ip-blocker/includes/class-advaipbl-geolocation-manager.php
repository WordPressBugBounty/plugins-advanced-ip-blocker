<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Geolocation_Manager {
    private $plugin;

    public function __construct(ADVAIPBL_Main $plugin_instance) {
        $this->plugin = $plugin_instance;
    }

        /**
     * Obtiene los datos de geolocalización para una IP, usando el método configurado.
     *
     * @param string $ip La dirección IP.
     * @return array|null Los datos de ubicación.
     */
    public function fetch_location( $ip ) {
        $main_instance = $this->plugin;
        $method = $main_instance->options['geolocation_method'] ?? 'api';
        
        // --- API EN TIEMPO REAL (CON CACHÉ) ---
        $cache_key = 'advaipbl_geo_loc_' . md5($ip);
        $cached_location = get_transient($cache_key);

        if ($cached_location !== false) {
            return $cached_location;
        }

        $location = null;
        $used_api = false;

        if ( 'local_db' === $method ) {
            // Nos aseguramos de que geoip_manager es una instancia válida y no una stdClass.
            if ( $main_instance->geoip_manager instanceof ADVAIPBL_GeoIP_Manager ) {
                $location = $main_instance->geoip_manager->lookup_ip( $ip );
            }
        }  
        
        // Si no tenemos ubicación válida (fallo local o modo api), llamamos a la API principal
        if ( empty($location) || !empty($location['error']) ) {
            $location = $this->fetch_location_from_api( $ip );
            $used_api = true;
        }

        // --- FALLBACK IPQUERY.IO PARA ASN VACÍO ---
        if ( $location && empty($location['error']) && empty($location['as']) ) {
            $location = $this->fetch_fallback_asn_from_ipquery( $ip, $location );
            $used_api = true; // Forzamos el cacheo si hemos usado el fallback
        }

        // Solo cacheamos si hemos usado una API (para no llenar transients si solo leemos local_db rápido)
        // Cacheamos por 24 horas para mantener datos actualizados.
        if ( $used_api && $location && ! isset( $location['error'] ) ) {
            set_transient( $cache_key, $location, DAY_IN_SECONDS );
        }

        return $location;
    }

    /**
     * Fallback to ipquery.io if the primary provider did not return an ASN.
     *
     * @param string $ip
     * @param array $location
     * @return array
     */
    private function fetch_fallback_asn_from_ipquery( $ip, $location ) {
        if ( get_transient( 'advaipbl_geo_fallback_down' ) ) {
            return $location; // Return original if fallback is circuit-broken
        }

        $url = 'https://api.ipquery.io/' . $ip;
        $response = wp_remote_get($url, ['timeout' => 3]);

        if (is_wp_error($response)) {
            set_transient( 'advaipbl_geo_fallback_down', true, 5 * MINUTE_IN_SECONDS );
            return $location;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            if (in_array($code, [400, 429, 500])) {
                $this->plugin->log_event("IPQuery Fallback Error: HTTP $code for IP $ip", 'warning', ['ip' => $ip]);
                set_transient( 'advaipbl_geo_fallback_down', true, 5 * MINUTE_IN_SECONDS );
            }
            return $location;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if ($data && !empty($data['isp']['asn'])) {
            $location['as'] = $data['isp']['asn'];
            if (empty($location['isp']) && !empty($data['isp']['isp'])) {
                $location['isp'] = $data['isp']['isp'];
            }
        }

        return $location;
    }

    /**
     * Obtiene los datos de geolocalización desde una API externa.
     * (Esta es la lógica de tu antigua función fetch_location)
     *
     * @param string $ip
     * @return array|null
     */
    private function fetch_location_from_api( $ip ) {
        $main_instance = ADVAIPBL_Main::get_instance();
        $provider = $main_instance->options['geolocation_provider'] ?? 'ip-api.com';

        // Check Circuit Breaker (Global API Timeout)
        if ( get_transient( 'advaipbl_geo_api_down_' . $provider ) ) {
            return ['error' => true, 'error_message' => 'API is temporarily unreachable (Circuit Breaker Active)'];
        }

        $api_key_transient = get_transient('advaipbl_transient_api_key_' . $provider);
        $api_key = $api_key_transient ?: ($main_instance->options['api_key_' . str_replace('.', '', $provider)] ?? '');

        $url = '';
        switch ($provider) {
            case 'ip-api.com':
                if ( ! empty( $api_key ) ) {
                    // Si hay una API key, SIEMPRE usamos el endpoint Pro sobre HTTPS.
                    $url = sprintf('https://pro.ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,as,query&key=%s', $ip, $api_key);
                } else {
                    // Si NO hay API key, SIEMPRE usamos el endpoint gratuito sobre HTTP.
                    $url = sprintf('http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,as,query', $ip);
                }
                break;
            case 'geoiplookup.net':
                $url = 'https://json.geoiplookup.io/' . $ip;
                break;
            case 'ipinfo.io':
                $url = 'https://ipinfo.io/' . $ip . '/json?token=' . $api_key;
                break;
            case 'ipapi.com':
                $url = 'http://api.ipapi.com/' . $ip . '?access_key=' . $api_key;
                break;
            case 'ipstack.com':
                $url = 'http://api.ipstack.com/' . $ip . '?access_key=' . $api_key;
                break;
            default:
                return ['error' => true, 'error_message' => 'Invalid provider configured.'];
        }

        // Limit timeout to 3 seconds instead of 10 to prevent hanging the whole site
        $response = wp_remote_get($url, ['timeout' => 3]);

        if (is_wp_error($response)) {
            // Activate Circuit Breaker for 5 minutes if there's a connection error
            set_transient( 'advaipbl_geo_api_down_' . $provider, true, 5 * MINUTE_IN_SECONDS );
            return ['error' => true, 'error_message' => $response->get_error_message()];
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!$data) {
            // Activate Circuit Breaker for 5 minutes on malformed response
            set_transient( 'advaipbl_geo_api_down_' . $provider, true, 5 * MINUTE_IN_SECONDS );
            return ['error' => true, 'error_message' => 'Invalid response from API.'];
        }
        
        switch ($provider) {
            case 'ip-api.com':
                if (isset($data['status']) && $data['status'] === 'fail') return ['error' => true, 'error_message' => $data['message'] ?? 'API error'];
                return ['country' => $data['country'] ?? null, 'country_code' => $data['countryCode'] ?? null, 'region' => $data['regionName'] ?? null, 'city' => $data['city'] ?? null, 'lat' => $data['lat'] ?? null, 'lon' => $data['lon'] ?? null, 'isp' => $data['isp'] ?? null, 'as' => $data['as'] ?? null];
            case 'geoiplookup.net':
                return ['country' => $data['country_name'] ?? null, 'country_code' => $data['country_code'] ?? null, 'region' => $data['region'] ?? null, 'city' => $data['city'] ?? null, 'lat' => $data['latitude'] ?? null, 'lon' => $data['longitude'] ?? null, 'isp' => $data['isp'] ?? null, 'as' => $data['asn'] ?? null];
            case 'ipinfo.io':
                if (isset($data['error'])) return ['error' => true, 'error_message' => $data['error']['message'] ?? 'API error'];
                list($lat, $lon) = explode(',', $data['loc'] ?? ',');
                return ['country' => $data['country'] ?? null, 'country_code' => $data['country'] ?? null, 'region' => $data['region'] ?? null, 'city' => $data['city'] ?? null, 'lat' => $lat ?? null, 'lon' => $lon ?? null, 'isp' => $data['org'] ?? null, 'as' => $data['org'] ?? null];
            case 'ipapi.com':
            case 'ipstack.com':
                if (isset($data['error'])) return ['error' => true, 'error_message' => $data['error']['info'] ?? 'API error'];
                return ['country' => $data['country_name'] ?? null, 'country_code' => $data['country_code'] ?? null, 'region' => $data['region_name'] ?? null, 'city' => $data['city'] ?? null, 'lat' => $data['latitude'] ?? null, 'lon' => $data['longitude'] ?? null, 'isp' => null, 'as' => null];
        }
        return null;
    }
	
	/**
 * Guarda temporalmente una clave de API en un transient para su verificación.
 *
 * @param string $provider El proveedor de la API.
 * @param string $api_key La clave de la API.
 */
public function set_transient_api_key($provider, $api_key) {
    set_transient('advaipbl_transient_api_key_' . $provider, $api_key, 60); // 60 segundos de vida
}

/**
 * Elimina la clave de API temporal después de la verificación.
 *
 * @param string $provider El proveedor de la API.
 */
public function clear_transient_api_key($provider) {
    delete_transient('advaipbl_transient_api_key_' . $provider);
}
}