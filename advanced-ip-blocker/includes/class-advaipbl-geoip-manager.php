<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_GeoIP_Manager
{
    public const DB_CITY_FILENAME    = 'GeoLite2-City.mmdb';
    public const DB_COUNTRY_FILENAME = 'GeoLite2-Country.mmdb';
    public const DB_ASN_FILENAME     = 'GeoLite2-ASN.mmdb';

    private $main_class;

    private $upload_dir_info;

    public function __construct(ADVAIPBL_Main $main_class)
    {
        $this->main_class = $main_class;
        $this->upload_dir_info = wp_upload_dir();
    }

    /**
     * Returns the full path to the directory where GeoIP databases are saved.
     * @return string
     */
    public function get_db_path()
    {
        $path = $this->upload_dir_info['basedir'] . '/advaipbl_geoip/';
        if (! is_dir($path)) {
            wp_mkdir_p($path);
        }

        if (! file_exists($path . '.htaccess')) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents($path . '.htaccess', 'deny from all');
        }
        if (! file_exists($path . 'index.php')) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents($path . 'index.php', '<?php // Silence is golden');
        }

        return $path;
    }

    /**
     * Returns status information of the local database files.
     * @return array
     */
    public function get_database_status()
    {
        $path = $this->get_db_path();
        $city_db_path = $path . self::DB_CITY_FILENAME;
        $country_db_path = $path . self::DB_COUNTRY_FILENAME;
        $asn_db_path = $path . self::DB_ASN_FILENAME;

        return [
            'city_db_exists'    => file_exists($city_db_path),
            'city_db_size'      => file_exists($city_db_path) ? size_format(filesize($city_db_path), 2) : 0,
            'city_db_date'      => file_exists($city_db_path) ? gmdate('Y-m-d H:i:s', filemtime($city_db_path)) : null,
            'country_db_exists' => file_exists($country_db_path),
            'country_db_size'   => file_exists($country_db_path) ? size_format(filesize($country_db_path), 2) : 0,
            'country_db_date'   => file_exists($country_db_path) ? gmdate('Y-m-d H:i:s', filemtime($country_db_path)) : null,
            'asn_db_exists'     => file_exists($asn_db_path),
            'asn_db_size'       => file_exists($asn_db_path) ? size_format(filesize($asn_db_path), 2) : 0,
            'asn_db_date'       => file_exists($asn_db_path) ? gmdate('Y-m-d H:i:s', filemtime($asn_db_path)) : null,
        ];
    }

    /**
     * Downloads and decompresses MaxMind GeoLite2 databases.
     *
     * @return array An array with 'success' (bool) and 'message' (string).
     */
    public function download_and_unpack_databases()
    {
        $license_key = $this->main_class->options['maxmind_license_key'] ?? '';
        if (empty($license_key)) {
            return ['success' => false, 'message' => __('MaxMind License Key is missing.', 'advanced-ip-blocker')];
        }

        require_once(ABSPATH . 'wp-admin/includes/file.php');
        WP_Filesystem();
        global $wp_filesystem;

        $db_path = $this->get_db_path();
        $databases = [
            'GeoLite2-City'    => sprintf('https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz', $license_key),
            'GeoLite2-Country' => sprintf('https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz', $license_key),
            'GeoLite2-ASN'     => sprintf('https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=%s&suffix=tar.gz', $license_key),
        ];

        foreach ($databases as $db_name => $url) {
            $response = wp_remote_get($url, [
                'timeout' => 300,
                'user-agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
            ]);

            if (is_wp_error($response)) {
                return ['success' => false, 'message' => sprintf('Failed to download %s: %s', $db_name, $response->get_error_message())];
            }

            $response_code = wp_remote_retrieve_response_code($response);
            if ($response_code !== 200) {
                if ($response_code === 401) {
                    return ['success' => false, 'message' => sprintf('Failed to download %s: Unauthorized (401). Please check if your MaxMind License Key is correct and active.', $db_name)];
                }

                return ['success' => false, 'message' => sprintf('Failed to download %s: Server returned status code %d.', $db_name, $response_code)];
            }

            $temp_file = wp_tempnam($db_name);
            $file_content = wp_remote_retrieve_body($response);

            if (! $wp_filesystem->put_contents($temp_file, $file_content)) {
                $wp_filesystem->delete($temp_file);

                return ['success' => false, 'message' => 'Could not write temporary file.'];
            }

            if (function_exists('ini_set') && function_exists('wp_convert_hr_to_bytes')) {
                $current_limit = @ini_get('memory_limit');
                $current_limit_int = wp_convert_hr_to_bytes($current_limit);
                if ($current_limit_int !== -1 && $current_limit_int < 536870912) {
                    // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
                    @ini_set('memory_limit', '512M');
                }
            } elseif (function_exists('ini_set')) {
                // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
                @ini_set('memory_limit', '512M');
            }

            try {
                $phar = new PharData($temp_file);
                $phar->extractTo($db_path, null, true);

                $extracted_folder_path = '';

                $iterator = new DirectoryIterator($db_path);
                foreach ($iterator as $fileinfo) {
                    if ($fileinfo->isDir() && !$fileinfo->isDot() && strpos($fileinfo->getFilename(), $db_name . '_') === 0) {
                        $extracted_folder_path = $fileinfo->getPathname();
                        break;
                    }
                }

                if (! empty($extracted_folder_path)) {
                    $source_mmdb = $extracted_folder_path . '/' . $db_name . '.mmdb';
                    $destination_mmdb = $db_path . $db_name . '.mmdb';

                    if ($wp_filesystem->exists($source_mmdb)) {
                        $wp_filesystem->move($source_mmdb, $destination_mmdb, true);
                        $wp_filesystem->delete($extracted_folder_path, true);
                    }
                }
            } catch (Exception $e) {
                global $wp_filesystem;
                if (! empty($wp_filesystem) && is_object($wp_filesystem)) {
                    $wp_filesystem->delete($temp_file);
                }

                return ['success' => false, 'message' => sprintf('Failed to decompress %s: %s', $db_name, $e->getMessage())];
            }

            global $wp_filesystem;
            if (! empty($wp_filesystem) && is_object($wp_filesystem)) {
                $wp_filesystem->delete($temp_file);
            }
        }

        return ['success' => true, 'message' => __('GeoIP databases updated successfully.', 'advanced-ip-blocker')];
    }

    public function lookup_ip($ip)
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        $db_path = $this->get_db_path();
        $city_db_path = $db_path . self::DB_CITY_FILENAME;
        $asn_db_path = $db_path . self::DB_ASN_FILENAME;

        if (! file_exists($city_db_path) || ! file_exists($asn_db_path)) {
            return null;
        }

        $location_data = [];

        try {
            if (! class_exists('\GeoIp2\Database\Reader')) {
                $this->main_class->log_event('GeoIP Error: The GeoIp2 library classes cause a fatal error or are missing. Please reinstall the plugin.', 'critical');

                return ['error' => true, 'error_message' => 'GeoIP library missing.'];
            }

            $city_reader = new \GeoIp2\Database\Reader($city_db_path);
            $city_record = $city_reader->city($ip);

            $location_data['country'] = $city_record->country->name ?? null;
            $location_data['country_code'] = $city_record->country->isoCode ?? null;
            if (! empty($city_record->subdivisions)) {
                $location_data['region'] = $city_record->subdivisions[0]->name ?? null;
            } else {
                $location_data['region'] = null;
            }
            $location_data['city'] = $city_record->city->name ?? null;
            $location_data['lat'] = $city_record->location->latitude ?? null;
            $location_data['lon'] = $city_record->location->longitude ?? null;

            $asn_reader = new \GeoIp2\Database\Reader($asn_db_path);
            $asn_record = $asn_reader->asn($ip);

            $location_data['isp'] = $asn_record->autonomousSystemOrganization ?? null;
            $location_data['as'] = isset($asn_record->autonomousSystemNumber)
                ? 'AS' . $asn_record->autonomousSystemNumber . ' ' . $asn_record->autonomousSystemOrganization
                : null;
        } catch (\GeoIp2\Exception\AddressNotFoundException $e) {
            return ['error' => true, 'error_message' => 'IP address not found in GeoIP database.'];
        } catch (\MaxMind\Db\Reader\InvalidDatabaseException $e) {
            $this->main_class->log_event('GeoIP DB Error: Invalid or corrupt database file. Please re-download. Details: ' . $e->getMessage(), 'critical');

            return ['error' => true, 'error_message' => 'Corrupt GeoIP Database.'];
        } catch (\Throwable $e) {
            $error_details = sprintf(
                'A critical error occurred while reading the GeoIP database. Type: %s, Message: %s, File: %s, Line: %d',
                get_class($e),
                $e->getMessage(),
                $e->getFile(),
                $e->getLine()
            );
            $this->main_class->log_event($error_details, 'critical');

            return ['error' => true, 'error_message' => 'An unexpected error occurred during GeoIP lookup.'];
        }

        return $location_data;
    }
}
