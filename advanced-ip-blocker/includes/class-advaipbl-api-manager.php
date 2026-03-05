<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Api_Manager {
    private $options;
    private $transient_keys = [];

    public function __construct() {
        $this->options = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] );
    }

    public function set_transient_api_key($provider, $key) {
        $this->transient_keys[$provider] = $key;
    }

    public function clear_transient_api_key($provider) {
        unset($this->transient_keys[$provider]);
    }

    private function get_api_key_for($provider) {
        // Prioridad 1: Clave temporal para verificación
        if (isset($this->transient_keys[$provider])) {
            return $this->transient_keys[$provider];
        }
        // Prioridad 2: Clave guardada en las opciones
        $key_name = 'api_key_' . str_replace(['-', '.'], '', $provider);
        return $this->options[$key_name] ?? '';
    }

    public function fetch_location( $ip ) {
        $provider = $this->options['geolocation_provider'] ?? 'ip-api.com';

        switch ($provider) {
            case 'ipinfo.io': return $this->fetch_from_ipinfo($ip);
            case 'ipapi.com': return $this->fetch_from_ipapi($ip);
            case 'ipstack.com': return $this->fetch_from_ipstack($ip);
            case 'geoiplookup.net': return $this->fetch_from_geoiplookup($ip);
            case 'ip-api.com':
            default:
                return $this->fetch_from_ip_api($ip);
        }
    }

    private function fetch_from_ip_api($ip) {
        $api_key  = $this->get_api_key_for('ip-api.com');
        $protocol = !empty($api_key) ? 'https' : 'http';
        
        // Añadimos el campo 'as' para obtener el ASN
        $fields = 'status,message,country,countryCode,regionName,city,lat,lon,isp,org,as';
        $url = "{$protocol}://ip-api.com/json/{$ip}?fields={$fields}";

        if ( 'https' === $protocol ) {
            $url .= '&key=' . $api_key;
        }
        $response = wp_remote_get($url, ['timeout' => 5]);
        if (is_wp_error($response)) { return ['error' => true, 'error_message' => $response->get_error_message()]; }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (isset($body['status']) && 'success' === $body['status']) {
            return [
                'country' => $body['country'] ?? '', 'country_code' => $body['countryCode'] ?? '',
                'region' => $body['regionName'] ?? '', 'city' => $body['city'] ?? '',
                'lat' => $body['lat'] ?? '', 'lon' => $body['lon'] ?? '',
                'isp' => $body['isp'] ?? ($body['org'] ?? ''),
                'as' => $body['as'] ?? '', // Guardamos el ASN
            ];
        }
        return ['error' => true, 'error_message' => $body['message'] ?? __('Invalid response from ip-api.com', 'advanced-ip-blocker')];
    }

    private function fetch_from_geoiplookup($ip) {
        $url = "https://json.geoiplookup.io/{$ip}";
        $response = wp_remote_get($url, ['timeout' => 5]);
        if (is_wp_error($response)) { return ['error' => true, 'error_message' => $response->get_error_message()]; }
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!empty($body['country_code'])) {
            return [ 'country' => $body['country_name'] ?? '', 'country_code' => $body['country_code'] ?? '', 'region' => $body['region'] ?? '', 'city' => $body['city'] ?? '', 'lat' => $body['latitude'] ?? '', 'lon' => $body['longitude'] ?? '', 'isp' => $body['isp'] ?? '' ];
        }
        return ['error' => true, 'error_message' => $body['error'] ?? __('Invalid response from geoiplookup.io', 'advanced-ip-blocker')];
    }

    private function fetch_from_ipinfo($ip) {
        $api_key = $this->get_api_key_for('ipinfo.io');
        $url = "https://ipinfo.io/{$ip}";
        
        
        if ( !empty($api_key) ) {
            $url .= '?token=' . esc_attr($api_key);
        }
        
        $args = [
        'timeout' => 5,
        'headers' => [
            'Accept'     => 'application/json',
            'User-Agent' => 'Mozilla/5.0 (WordPress; ' . get_bloginfo('url') . ')',
            'Referer'    => get_bloginfo('url')
           ]
        ];
    

        $response = wp_remote_get($url, $args);
        if (is_wp_error($response)) { return ['error' => true, 'error_message' => $response->get_error_message()]; }
        
        $http_code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        if ($http_code !== 200) {
            $error_msg = $body['error']['message'] ?? "HTTP error {$http_code}";
            return ['error' => true, 'error_message' => $error_msg];
        }

        if (isset($body['bogon'])) {
            return ['error' => true, 'error_message' => 'Private or reserved IP address.'];
        }

        if (!empty($body['country'])) {
            list($lat, $lon) = explode(',', $body['loc'] ?? '0,0');
            return [
                'country' => $body['country'] ?? '', 'country_code' => $body['country'] ?? '',
                'region' => $body['region'] ?? '', 'city' => $body['city'] ?? '',
                'lat' => $lat, 'lon' => $lon,
                'isp' => $body['org'] ?? '',
                'asn' => $body['asn'] ?? [],
            ];
        }
        return ['error' => true, 'error_message' => __('Invalid response from ipinfo.io', 'advanced-ip-blocker')];
    }

    private function fetch_from_ipapi($ip) {
        $api_key = $this->get_api_key_for('ipapi.com');
		/* translators: %s: ipapi.com */
        if (empty($api_key)) { return ['error' => true, 'error_message' => sprintf( __('API Key is required for %s', 'advanced-ip-blocker'), 'ipapi.com' )]; }
        
        $url = "http://api.ipapi.com/api/{$ip}?access_key=" . esc_attr($api_key);
        $response = wp_remote_get($url, ['timeout' => 5]);
        if (is_wp_error($response)) { return ['error' => true, 'error_message' => $response->get_error_message()]; }
        
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        // Lógica de error específica para ipapi.com
        if (isset($body['success']) && false === $body['success']) {
            return ['error' => true, 'error_message' => $body['error']['info'] ?? __('Unknown error from ipapi.com', 'advanced-ip-blocker')];
        }

        if (!empty($body['country_name'])) {
            return [ 'country' => $body['country_name'] ?? '', 'country_code' => $body['country_code'] ?? '', 'region' => $body['region_name'] ?? '', 'city' => $body['city'] ?? '', 'lat' => $body['latitude'] ?? '', 'lon' => $body['longitude'] ?? '', 'isp' => $body['connection']['isp'] ?? '' ];
        }
        return ['error' => true, 'error_message' => __('Invalid response from ipapi.com', 'advanced-ip-blocker')];
    }

    private function fetch_from_ipstack($ip) {
        $api_key = $this->get_api_key_for('ipstack.com');
		/* translators: %s: ipstack.com */
        if (empty($api_key)) { return ['error' => true, 'error_message' => sprintf( __('API Key is required for %s', 'advanced-ip-blocker'), 'ipstack.com' )]; }
        
        $url = "http://api.ipstack.com/{$ip}?access_key=" . esc_attr($api_key);
        $response = wp_remote_get($url, ['timeout' => 5]);
        if (is_wp_error($response)) { return ['error' => true, 'error_message' => $response->get_error_message()]; }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        // Lógica de error específica para ipstack.com
        if (isset($body['success']) && false === $body['success']) {
            return ['error' => true, 'error_message' => $body['error']['info'] ?? __('Unknown error from ipstack.com', 'advanced-ip-blocker')];
        }
        
        if (!empty($body['country_name'])) {
            return [ 'country' => $body['country_name'] ?? '', 'country_code' => $body['country_code'] ?? '', 'region' => $body['region_name'] ?? '', 'city' => $body['city'] ?? '', 'lat' => $body['latitude'] ?? '', 'lon' => $body['longitude'] ?? '', 'isp' => $body['connection']['isp'] ?? '' ];
        }
        return ['error' => true, 'error_message' => __('Invalid response from ipstack.com', 'advanced-ip-blocker')];
    }
}