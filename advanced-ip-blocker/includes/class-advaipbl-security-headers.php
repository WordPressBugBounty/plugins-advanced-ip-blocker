<?php

if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Security_Headers {

    private $plugin;
    const OPTION_NAME = 'advaipbl_security_headers';
    const OPTION_GROUP = 'advaipbl_security_headers_group';

    public function __construct(ADVAIPBL_Main $plugin) {
        $this->plugin = $plugin;
        add_action('send_headers', [$this, 'add_security_headers']);
        add_action('admin_init', [$this, 'register_settings']);
    }

    public function add_security_headers() {
        if (headers_sent() || is_admin()) {
            return;
        }
        $options = get_option(self::OPTION_NAME, $this->get_default_options());
        
        if (!is_array($options)) {
            return;
        }

        foreach ($options as $key => $header) {
            if (!empty($header['enabled']) && !empty($header['name']) && !empty($header['value'])) {
                if ($key === 'hsts' && !is_ssl()) {
                    continue;
                }
                header(trim($header['name']) . ': ' . trim($header['value']), true);
            }
            if ($key === 'server_header' && !empty($header['enabled']) && $header['value'] === 'remove') {
                header_remove('Server');
            }
        }
    }

    public function register_settings() {
        register_setting(self::OPTION_GROUP, self::OPTION_NAME, [
            'sanitize_callback' => [$this, 'sanitize_options'],
            'default' => $this->get_default_options()
        ]);
    }

    public function get_default_options() {
        return [
            'referrer_policy' => ['name' => 'Referrer-Policy', 'value' => 'strict-origin-when-cross-origin', 'enabled' => true, 'description' => __('Controls referrer info sent to other sites.', 'advanced-ip-blocker')],
            'permissions_policy' => ['name' => 'Permissions-Policy', 'value' => 'microphone=(), camera=(), geolocation=()', 'enabled' => true, 'description' => __('Controls which browser features can be used.', 'advanced-ip-blocker')],
            'x_frame_options' => ['name' => 'X-Frame-Options', 'value' => 'SAMEORIGIN', 'enabled' => true, 'description' => __('Protects against clickjacking attacks.', 'advanced-ip-blocker')],
            'x_content_type_options' => ['name' => 'X-Content-Type-Options', 'value' => 'nosniff', 'enabled' => true, 'description' => __('Prevents MIME-sniffing vulnerabilities.', 'advanced-ip-blocker')],
            'hsts' => ['name' => 'Strict-Transport-Security', 'value' => 'max-age=31536000; includeSubDomains; preload', 'enabled' => true, 'description' => __('<strong>Warning:</strong> Only use if your site is fully on HTTPS.', 'advanced-ip-blocker')],
            'csp' => ['name' => 'Content-Security-Policy', 'value' => "", 'enabled' => false, 'description' => __('<strong>Enforcing CSP.</strong> Build your policy using the Report-Only mode below first. <strong>Warning:</strong> Incorrect CSP can break your site.', 'advanced-ip-blocker')],
            'csp_report_only' => ['name' => 'Content-Security-Policy-Report-Only', 'value' => "default-src 'self';", 'enabled' => false, 'description' => __('<strong>CSP Report-Only Mode.</strong> Use this to test your policy.', 'advanced-ip-blocker')],
            'server_header' => ['name' => 'Server', 'value' => '', 'enabled' => false, 'description' => __('Modify or remove the "Server" header. To remove, set value to "remove". Obfuscates server technology.', 'advanced-ip-blocker')],
            'custom_1' => ['name' => '', 'value' => '', 'enabled' => false, 'description' => __('Define a custom header. Example: X-Forwarded-For', 'advanced-ip-blocker')],
            'custom_2' => ['name' => '', 'value' => '', 'enabled' => false, 'description' => __('Define another custom header.', 'advanced-ip-blocker')],
            'custom_3' => ['name' => '', 'value' => '', 'enabled' => false, 'description' => __('Define a third custom header.', 'advanced-ip-blocker')],
        ];
    }

    public function sanitize_options($input) {
        $defaults = $this->get_default_options();
        $output = [];
        foreach ($defaults as $key => $values) {
            $output[$key]['description'] = $values['description'];
            $output[$key]['enabled'] = !empty($input[$key]['enabled']) ? 1 : 0;
            $output[$key]['name'] = isset($input[$key]['name']) ? sanitize_text_field($input[$key]['name']) : $values['name'];
            if ($key === 'csp' || $key === 'csp_report_only') {
                 // CSP can contain various chars, stripping tags is usually enough but we must be careful.
                 // wp_kses_post allows too much HTML. sanitize_text_field strips too much (quotes).
                 // We will use a custom sanitization that preserves CSP syntax but removes tags.
                $output[$key]['value'] = isset($input[$key]['value']) ? $this->sanitize_csp($input[$key]['value']) : '';
            } else {
                $output[$key]['value'] = isset($input[$key]['value']) ? sanitize_text_field($input[$key]['value']) : '';
            }
        }
        return $output;
    }

    private function sanitize_csp($value) {
        // Strip tags but allow quotes, semicolons, etc.
        return wp_strip_all_tags($value);
    }

    public function display_settings_tab() {
        if (!current_user_can('manage_options')) return;
        ?>
        <style>
            .shc-container{display:grid;grid-template-columns:1fr;gap:20px; margin-top: 20px;}
            .shc-card{border:1px solid #c3c4c7;border-left-width:4px;background:#fff;box-shadow:0 1px 1px rgba(0,0,0,.04);transition:border-color .3s ease; padding: 0;}
            .shc-card.is-enabled{border-left-color:#00a32a}
            .shc-card.is-disabled{border-left-color:#d63638}
            .shc-card-header{padding:12px 15px;border-bottom:1px solid #ddd;display:flex;justify-content:space-between;align-items:center; background: #fafafa;}
            .shc-card-header h3{font-size:1.1em;margin:0;padding:0}
            .shc-card-body{padding:15px}
            .shc-form-field{margin-bottom:15px}
            .shc-form-field label{font-weight:600;display:block;margin-bottom:5px}
            .shc-form-field .regular-text,.shc-form-field .large-text{width:100%}
            .shc-form-field .description{font-style:italic;color:#646970; margin-bottom: 15px; display: block;}
            .shc-switch{position:relative;display:inline-block;width:50px;height:24px}
            .shc-switch input{opacity:0;width:0;height:0}
            .shc-slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:#ccc;transition:.4s;border-radius:24px}
            .shc-slider:before{position:absolute;content:"";height:16px;width:16px;left:4px;bottom:4px;background-color:white;transition:.4s;border-radius:50%}
            input:checked+.shc-slider{background-color:#007cba}
            input:focus+.shc-slider{box-shadow:0 0 1px #007cba}
            input:checked+.shc-slider:before{transform:translateX(26px)}
        </style>
        
        <h2>
            <?php esc_html_e('Security Headers', 'advanced-ip-blocker'); ?>
            <a href="https://advaipbl.com/implement-http-security-headers/" target="_blank" class="dashicons dashicons-editor-help" style="text-decoration: none; font-size: 20px; vertical-align: middle; color: #72777c;" title="<?php esc_attr_e('Read documentation', 'advanced-ip-blocker'); ?>"></a>
        </h2>
        <p><?php esc_html_e('Manage the HTTP Security Headers sent by your website to improve browser-side security.', 'advanced-ip-blocker'); ?></p>
        
        <div class="notice notice-info inline">
            <p><?php esc_html_e('Note: These headers are sent via PHP. If you have similar headers configured in your .htaccess file, they might work together or override each other depending on your server configuration. If unsure, checking your headers at securityheaders.com after saving is recommended.', 'advanced-ip-blocker'); ?></p>
        </div>
        
        <form action="options.php" method="post">
            <?php
            settings_fields(self::OPTION_GROUP);
            $options = get_option(self::OPTION_NAME, $this->get_default_options());
            $defaults = $this->get_default_options();
            
            // Merge defaults to ensure all keys exist
            $options = array_merge($defaults, is_array($options) ? $options : []);
            ?>
            <div class="shc-container">
                <?php foreach ($options as $key => $header): ?>
                    <?php $is_enabled = !empty($header['enabled']); ?>
                    <div class="shc-card <?php echo $is_enabled ? 'is-enabled' : 'is-disabled'; ?>">
                        <div class="shc-card-header">
                            <h3><?php echo esc_html($defaults[$key]['name'] ?: __('Custom Header', 'advanced-ip-blocker')); ?></h3>
                            <label class="shc-switch">
                                <input name="<?php echo esc_attr(self::OPTION_NAME); ?>[<?php echo esc_attr($key); ?>][enabled]" type="checkbox" value="1" <?php checked(1, $is_enabled); ?>>
                                <span class="shc-slider"></span>
                            </label>
                        </div>
                        <div class="shc-card-body">
                            <span class="description"><?php echo wp_kses_post($header['description']); ?></span>
                            <div class="shc-form-field">
                                <label for="shc_<?php echo esc_attr($key); ?>_name"><?php esc_html_e('Header Name', 'advanced-ip-blocker'); ?></label>
                                <input name="<?php echo esc_attr(self::OPTION_NAME); ?>[<?php echo esc_attr($key); ?>][name]" type="text" id="shc_<?php echo esc_attr($key); ?>_name" value="<?php echo esc_attr($header['name'] ?? ''); ?>" class="regular-text">
                            </div>
                            <div class="shc-form-field">
                                <label for="shc_<?php echo esc_attr($key); ?>_value"><?php esc_html_e('Header Value', 'advanced-ip-blocker'); ?></label>
                                <?php if ($key === 'csp' || $key === 'csp_report_only'): ?>
                                    <textarea name="<?php echo esc_attr(self::OPTION_NAME); ?>[<?php echo esc_attr($key); ?>][value]" id="shc_<?php echo esc_attr($key); ?>_value" class="large-text" rows="4"><?php echo esc_textarea($header['value'] ?? ''); ?></textarea>
                                <?php else: ?>
                                    <input name="<?php echo esc_attr(self::OPTION_NAME); ?>[<?php echo esc_attr($key); ?>][value]" type="text" id="shc_<?php echo esc_attr($key); ?>_value" value="<?php echo esc_attr($header['value'] ?? ''); ?>" class="large-text">
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
            <?php submit_button(__('Save Security Headers', 'advanced-ip-blocker')); ?>
        </form>
        <?php
    }
}