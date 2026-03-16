=== Advanced IP Blocker ===
Contributors: inilerm
Author URI: https://advaipbl.com/
Donate link: https://donate.stripe.com/bJe00kaIP89O1wFfargUM00
Tags: security, firewall, waf, ip blocker, country block, brute force, block ip, rate limit, 2fa, two-factor
Requires at least: 6.7
Tested up to: 6.9
Stable tag: 8.9.3
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A complete WordPress security firewall: blocks IPs, bots & countries. Includes an intelligent WAF, Threat Scoring, Geo-Challenge, 2FA, and Anti-Spoofing.

== Description ==

**Advanced IP Blocker** is your all-in-one security solution to safeguard your WordPress website from a wide range of threats. This plugin provides a comprehensive suite of tools to automatically detect and block malicious activity, including brute-force attacks, vulnerability scanning, and spam bots. With its intuitive interface, you can easily manage whitelists, blocklists, and view detailed security logs to understand exactly how your site is being protected.

> **Important Note on PHP Version:**
> To ensure maximum security and access to all features, we strongly recommend using **PHP 8.1 or higher**. Some advanced features (like the local MaxMind database or full 2FA management via WP-CLI) require PHP 8.1.

**Key Features:**
*   **(NEW) Country Selector Copy/Paste:** Say goodbye to manually selecting 50+ countries. You can now instantly copy and paste a raw list of 2-letter country codes directly into Geoblocking, Geo-Challenge, and Whitelist Login fields.
*   **(NEW) AIB Cloud Network V3:** Upgrade to the next-generation distributed threat intelligence network. The new API V3 provides secure, individual API Keys per site, drastically improving synchronization reliability, threat telemetry, and global network stability.
*   **(NEW) Whitelist Login Countries:** Take absolute control over administrative access. Easily restrict your WordPress login page and XML-RPC to only allow connections from specific, whitelisted countries, instantly blocking unauthorized foreign login attempts.
*   **(IMPROVED) Bulk Import/Export for Blocked IPs & Whitelist:** Seamlessly import massive lists of IPs via CSV or manual entry. The system now features a bulletproof "Bulk Import" type, strict duration inheritance, and intelligent conflict resolution.
*   **(NEW) Internal Security & Forensics:** A complete audit suite solely for WordPress. Track every sensitive event (plugin installs, settings changes, user logins) and monitor your critical files for unauthorized modifications with the integrated File Integrity Monitor.
*   **(NEW) Activity Audit Log:** Gain complete visibility into what's happening on your site. Who deactivated a plugin? Who changed a setting? The Audit Log answers these questions with timestamped, immutable records.
*   **(NEW) Deep Scan Email Reports:** Get a weekly security summary delivered to your inbox, detailing pending updates, vulnerability status, and recent attack trends.
*   **Username Blocking & Rules:** Gain granular control over login security. Creating Advanced Rules to block, challenge, or score specific usernames (e.g., "admin", "test").
*   **Enhanced Lockdown Notifications:** Distributed Lockdowns (404/403) now fully support Email and Push notifications, ensuring you never miss a critical security event.
*   **Improved Logging:** New "Endpoint Challenge" event type provides deeper visibility into challenges served during automated lockdowns.
*   **Server IP Reputation Check. Instantly audit your web server's IP address against major blacklists (Spamhaus, AbuseIPDB) to diagnose SEO and email delivery issues.
*   **HTTP Security Headers.** Easily configure essential security headers like HSTS, X-Frame-Options, and Permissions-Policy to harden your site against clickjacking, sniffing, and other browser-based attacks. Includes a "Report-Only" mode for CSP.
*   **Site Health & Vulnerability Scanner. Audit your WordPress environment instantly. Detects outdated plugins, insecure PHP versions, and checks your installed plugins against a database of 30,000+ known vulnerabilities.
*   **PERFORMANCE BOOST: High-Speed Community Database. Migrated the "Community Defense Network" blocklist to a dedicated, indexed database table. This allows checking thousands of malicious IPs in microseconds with zero impact on site memory usage.
*   **WordPress 6.9 Ready. Fully tested and compatible with the latest WordPress core update.
*   **Community Defense Network. Join forces with other WordPress admins. The plugin now shares anonymous attack data to build a global, real-time blocklist of verified threats. Protect your site with community-powered intelligence.
*   **Auto-Cleaning Logic. Smart expiration handling ensures your blocklists stay fresh and performant, automatically removing stale IPs from both the database and external firewalls (Cloudflare/.htaccess).
*   **Cloud Edge Defense (Cloudflare). Connect your site directly to Cloudflare's global network. Automatically sync your blocklists to the cloud to stop attackers before they reach your server. Zero server load protection.
*   **Server-Level Firewall (.htaccess). Extreme performance upgrade. Write blocking rules and file hardening protections directly to your .htaccess file. Blocks threats instantly without loading PHP or WordPress.
*   **IMPROVED: Smart Bot Verification. Enhanced logic to correctly identify legitimate traffic from iOS devices (iCloud Private Relay) and social media previews, eliminating false positives while keeping impostors out.
*   **File Hardening.** Protect your most sensitive files (`wp-config.php`, `readme.html`, `.git`) at the server level with a single click.
*   **AbuseIPDB Integration.** Proactively block attackers before they strike. The plugin can now check visitor IPs against AbuseIPDB's real-time, crowdsourced database of malicious IPs and block those with a high abuse score on their very first request.
*   **Edge Firewall Mode!** Protect any PHP file or standalone application within your WordPress directory (even if it's not part of WordPress). Ideal for securing custom scripts, legacy applications, or folders like `/scan/`. (Requires manual configuration).
*   **Advanced Rules Engine!** Create powerful, custom security rules with multiple conditions (IP, Country, ASN, URI, User-Agent) and actions (Block, Challenge, or add Threat Score).
*   **Known Bot Verification.** A powerful new security layer that uses reverse DNS lookups to verify legitimate crawlers like Googlebot and Bingbot. This completely neutralizes attackers who try to bypass security rules by faking their User-Agent, assigning high threat scores to impostors.
*   **Onboarding Setup Wizard.** A brand new step-by-step wizard that guides new users through the essential security configurations (IP whitelisting, WAF, and bot traps) in under a minute, ensuring a strong security posture from day one.
*   **Major Refactor: Codebase Modernization.** The entire plugin architecture has been refactored into a modern, modular structure. Logic for admin pages, AJAX, actions, and settings is now handled by dedicated classes, making the plugin more stable, performant, and easier to maintain and extend in the future.
*   **Advanced IP Spoofing Protection.** A zero-trust "Trusted Proxies" system ensures the plugin always identifies the true visitor IP, even behind complex setups like Cloudflare or a custom reverse proxy. It neutralizes attacks that attempt to fake their IP, preventing block evasion and the framing of innocent users.
*   **Geo-Challenge.** A smarter way to handle traffic from high-risk countries. Instead of a hard block, it presents a quick, invisible JavaScript challenge that stops bots but is seamless for human visitors. This reduces unwanted traffic without affecting potential legitimate users.
*   **ENHANCEMENT: Full Bulk-Action Support.** IP management is now faster than ever. Both the Whitelist and the Blocked IPs list now support full bulk actions, allowing you to select and remove multiple entries at once, or unblock all IPs with a single click.
*   **Endpoint Lockdown Mode:** Automatically shields `wp-login.php` and `xmlrpc.php` with a JavaScript challenge during sustained distributed attacks, preventing server overload.
*   **Two-Factor Authentication (2FA):** Secure user accounts with industry-standard TOTP authentication, backup codes, role enforcement, and a central admin management dashboard.
*   **IP Trust & Threat Scoring System:** An intelligent defense that assigns "threat points" to IPs for malicious actions, blocking them only when they reach a configurable score. More accurate and context-aware than simple rules.
*   **Attack Signature Engine (Beta):** Proactively stops distributed botnet attacks by identifying and blocking the attacker's "fingerprint" (signature) instead of just individual IPs.
*   **Web Application Firewall (WAF):** Block malicious requests (SQLi, XSS, etc.) with a customizable ruleset.
*   **And much more:** Rate Limiting, Country & ASN Blocking (with Spamhaus support), ASN Whitelisting, Push Notifications, Google reCAPTCHA, Honeypots, Active User Session Management, and Full WP-CLI Support.


== Installation ==

1.  Upload the `advanced-ip-blocker` folder to the `/wp-content/plugins/` directory.
2.  Activate the plugin through the 'Plugins' menu in WordPress.
3.  A new **"Security"** menu item will appear in your admin sidebar. All settings are located there.
4.  **Crucial:** Visit `Security > Dashboard > System Status` to ensure your IP and your server's IP are whitelisted. Use the one-click buttons if they are not.

== Frequently Asked Questions ==
= How does the Vulnerability Scanner work? =
The scanner checks your site in two ways:
Local Scan: Checks for outdated PHP versions, WordPress core updates, debug mode risks, and SSL status. This runs locally and instantly.
Deep Scan (Vulnerability Audit): Checks your installed plugins and themes against our central database of known security vulnerabilities (CVEs). This process is manual (you click a button) to ensure it never slows down your site during normal operation.

= What is the new Audit Log? =
The Audit Log is your site's "black box". It records critical administrative actions such as plugin activations, settings changes, and file modifications. This helps you identify "who did what and when," which is essential for troubleshooting and security forensics.

= How does the File Integrity Monitor (FIM) work? =
The FIM scans your critical core files (wp-config.php, .htaccess, index.php) and specific plugin files daily. It takes a "fingerprint" (hash) of the file. If the file changes (e.g., malware adds a line of code), the fingerprint changes, and the plugin alerts you immediately via email.

= Why did you move the Community Blocklist to a custom table? =
To ensure maximum performance as the network grows. Storing thousands of IPs in standard WordPress options (wp_options) can slow down a site. By moving this data to a dedicated, indexed database table (wp_advaipbl_community_ips), we ensure that lookups are lightning-fast (O(1) complexity) and consume negligible memory, regardless of how many threats we track.

= What is the Community Defense Network? =
It is a collaborative security feature where users share anonymized data about verified attacks (like SQL injections caught by the WAF or IPs flagged by AbuseIPDB). Our central server aggregates this data to create a global blocklist of active threats. You can choose to contribute data ("Join") and/or use the global list to protect your site ("Enable Blocking").

= Does the Community Network slow down my site? =
No. The data sharing happens in the background via a low-priority scheduled task (Cron) just a few times a day. The global blocklist is downloaded locally and cached, so checking an IP against it is instant (microseconds) and does not require external API calls.

= How do I set up Cloud Edge Defense (Cloudflare)? =
You need a free Cloudflare account and your domain must be using Cloudflare's nameservers.
1. Go to Security > Settings > Cloud Edge Defense.
2. Enter your Cloudflare API Token (with "Zone > Firewall Services > Edit" permissions) and Zone ID.
3. Click "Verify" and save.
The plugin will now automatically push your blocked IPs to Cloudflare's Firewall. For a step-by-step guide with screenshots, click the help icon in the settings or visit our website.

= Is the Server-Level Firewall (.htaccess) safe? =
Yes. Safety is our priority.
1. Backups: The plugin automatically creates a timestamped backup of your .htaccess file in a protected folder every time it writes new rules.
2. Compatibility: It automatically detects your server type and generates valid syntax for Apache 2.2 or 2.4.
3. Safety Limit: It includes a safety limit on the number of IPs written to the file to prevent server memory issues.

= What if I use Nginx instead of Apache? =
The "Server-Level Firewall (.htaccess)" feature relies on Apache/LiteSpeed specific files. If you use Nginx (without Apache), these local rules will be ignored by the server.
Recommendation: For Nginx users, we strongly recommend enabling the Cloud Edge Defense (Cloudflare) feature. It provides the same "pre-execution" blocking benefits but works on any server environment since the blocking happens in the cloud.

= How should I configure the plugin for my specific website? =
While every website's security needs are unique, here is a general guide to get you started. For a deep dive into every feature, please consult our [Comprehensive Feature Guide](https://advaipbl.com/comprehensive-feature-guide-advanced-ip-blocker/).
*   **Essential First Steps (All Sites):** After installation, run the Setup Wizard or manually go to `Security > Dashboard > System Status` to whitelist your IP and your server's IP. Then, enable logging.
*   **Blogs/Business Sites:** Enable the "IP Trust & Threat Scoring System", "WAF", "Rate Limiting", and "Spamhaus ASN Protection".
*   **E-commerce/Membership Sites:** Enable "Two-Factor Authentication (2FA)" for admin roles and use "Geo-Challenge" instead of hard geoblocking for countries where you have customers. **Do not** use "Whitelist Login Access".
*   **Sites with a CDN (Cloudflare):** Go to `Security > Settings > IP Detection` and add your CDN's ASN (e.g., `AS13335` for Cloudflare) to the "Trusted Proxies" list. This is critical for accurate IP detection.

= What is AbuseIPDB Protection and how does it work? =

AbuseIPDB is a global, crowdsourced project that tracks and reports malicious IP addresses in real-time. Our new integration allows the plugin to check the reputation of a new, unknown visitor against this database on their first visit. If the IP has been recently reported by others for activities like hacking, spam, or brute-force attacks, and its "abuse confidence score" is above your configured threshold, the plugin will block it instantly. This acts as a proactive shield against known bad actors, stopping them before they even have a chance to test your defenses. You can enable it and add your free API key under `Security > Settings > Threat Intelligence`.

= What is "Known Bot Verification"? =
This is an advanced security feature that checks if visitors claiming to be from major search engines (like Googlebot) are legitimate. It performs a DNS lookup to verify their IP address. If the check fails, the visitor is identified as an "impersonator" and receives a high threat score, preventing them from exploiting the trust given to real crawlers. This feature is enabled by default under `Settings > Core Protections`.

= What is "Trusted Proxies" and why do I need it? =
This is a critical security feature that prevents IP spoofing. If your site is behind a service like Cloudflare, Varnish, or another reverse proxy, the server's direct connection IP (`REMOTE_ADDR`) will always be the proxy's IP, not the visitor's. The real visitor IP is sent in an HTTP header (e.g., `CF-Connecting-IP`). An attacker can fake this header. The "Trusted Proxies" setting tells the plugin: "Only trust these headers if the request comes from an IP address I know is my proxy." You can add IPs, CIDR ranges, or ASNs (like `AS13335` for Cloudflare) to this list under `Security > Settings > IP Detection`.

= What is Geo-Challenge? How is it different from Geoblocking? =
**Geoblocking** is a hard block. It shows a "403 Access Denied" page to visitors from selected countries.
**Geo-Challenge** is a soft block. It shows a quick, automated JavaScript test to visitors from selected countries. Legitimate humans pass instantly, while most bots are stopped. This is useful for regions you are suspicious of but do not want to block entirely. You can, for example, block Country A and challenge Country B. You can configure it in `Security > Settings > Core Protections`.

= How do I solve issues with the JavaScript challenge and caching plugins? =
The JavaScript challenge (used by Geo-Challenge, Signature Engine, and Endpoint Lockdown) requires dynamic content. Aggressive page caching can interfere with it. If you experience issues (like a challenge loop or a "Verification failed" error), you must configure your caching plugin (e.g., WP Rocket, WP Fastest Cache, LiteSpeed Cache) to **NOT** cache pages for visitors who do not have the `advaipbl_js_verified` cookie. Most caching plugins have a setting like "Never cache pages that use this cookie."

= How do I solve issues with the JavaScript challenge and cookie consent (RGPD/GDPR) plugins? =
Cookie consent plugins (like CookieYes) may block our security cookie from being set. To fix this, you must go into your cookie plugin's settings and classify the cookie named `advaipbl_js_verified` as **"Strictly Necessary"** or "Essential". This will allow the security challenge to function correctly.

= What is the new "Local Database" Geolocation Method? =
For maximum performance, the plugin offers two ways to identify an IP's location (`Security > Settings > Geolocation`):
1.  **Real-time API (Default):** Easy to set up and great for most websites.
2.  **Local Database (Highest Performance):** Downloads the MaxMind GeoLite2 database to your server for instant, offline lookups with zero external API calls. Recommended for high-traffic sites. Requires a free MaxMind license key.

= How do I set up Two-Factor Authentication (2FA)? =
1.  **Admin:** Go to `Security > Settings > Login & User Protection` and enable 2FA globally. You can also enforce it for specific user roles.
2.  **User:** Go to your WordPress Profile page. You will find a new section to set up 2FA by scanning a QR code with an authenticator app and saving your backup codes.

= What is the "Attack Signature Engine"? =
This is an advanced defense that stops botnets by blocking the attacker's "fingerprint" (signature), not just their IP. It works in three phases you can enable in `Security > Settings > Signature Engine`: Logging, Analysis (a background task that finds patterns), and Blocking (presents a JS challenge to malicious signatures). You can manage detected signatures in `IP Management > Blocked Signatures`.

= What is the difference between the WAF, Signature Engine, and Advanced Rules? =

Think of them as three layers of defense:
1.  **WAF (Web Application Firewall):** The simplest layer. It blocks requests based on simple malicious patterns (e.g., `union select`). It's fast and stops common, generic attacks.
2.  **Attack Signature Engine:** The automated layer. It looks for patterns of attack from many different IPs (botnets) and blocks the attack's "fingerprint" (signature) for all visitors. You don't create these rules; the plugin does.
3.  **Advanced Rules Engine:** The manual control layer. This is where *you* build your own specific, multi-conditional rules. For example: "IF the visitor is from China AND is trying to access `/wp-admin/` THEN Block them permanently." It gives you the ultimate power to create a security policy tailored exactly to your site's needs.

= How should I configure the plugin for my specific website? =

While every website's security needs are unique, here is a general guide to get you started based on your site's profile. For a deep dive into every feature, please consult our [Comprehensive Feature Guide](https://advaipbl.com/comprehensive-feature-guide-advanced-ip-blocker/).

**1. Essential First Steps (For ALL Websites)**

No matter your site type, do these three things immediately after installation to ensure a strong baseline security without locking yourself out:

*   **Whitelist Your IPs:** Go to `Security > Dashboard > System Status` and use the one-click buttons to add your current IP and your server's IP to the whitelist. This is the most critical step.
*   **Activate Trap Defenses:** Go to `Security > Blocking Rules`, and in the "User Agents" and "Honeypot URLs" tabs, copy the suggested lists into the active blocklist text areas. This provides immediate protection from thousands of common bots.
*   **Enable Logging:** Go to `Security > Settings > General` and ensure "Enable Logging" is turned on. This gives you the visibility you need to understand what is happening on your site.

**2. Recommended Profiles**

Once the essentials are done, tailor the configuration to your site type:

**For a Standard Blog or Business Website:**
Your main goal is to block automated threats without affecting administrators.
*   **Enable the IP Trust & Threat Scoring System:** This is the smartest way to block bad actors contextually. The default point values are an excellent starting point. (Found in `Settings > IP Trust & Threat Scoring`).
*   **Enable the WAF and Rate Limiting:** These are powerful proactive defenses. (Found in `Settings > Core Protections` and `Threshold Blocking`).
*   **Enable Spamhaus ASN Protection:** Let the plugin automatically block thousands of known malicious networks for you. (Found in `Settings > Core Protections`).

**For an E-commerce or Membership Site (WooCommerce, etc.):**
You need to protect your site while ensuring legitimate customers from around the world are never blocked.
*   **Enable Two-Factor Authentication (2FA):** This is the single best way to protect administrator and shop manager accounts. Enforce it for these roles in `Settings > Login & User Protection`.
*   **Use Geo-Challenge Instead of Geoblocking:** If you receive attacks from a specific country but also have customers there, use the Geo-Challenge feature instead of a hard block. This will stop bots without affecting human users.
*   **CRITICAL: DO NOT USE "Whitelist Login Access".** This feature will lock out your customers.
*   **WAF Exclusions:** Double-check that URLs for your payment gateways (like Stripe or PayPal webhooks) are in the WAF exclusion list to ensure payments are processed correctly.

**For Any Site Using a CDN or Reverse Proxy (like Cloudflare):**
Your top priority is ensuring the plugin detects the correct visitor IP address.
*   **Configure Trusted Proxies:** Go to `Security > Settings > IP Detection`. Add the IPs or, even better, the ASNs of your CDN/proxy service to this list. For Cloudflare, simply add `AS13335` on a new line. This is essential for the accuracy of all other security features.

= How can I protect a non-WordPress folder on my site? =

This plugin includes an advanced "Edge Firewall Mode" that allows you to extend its protection to any PHP script on your server. This is perfect for securing custom applications or directories that are not managed by WordPress. To enable it, you need to add a single line of code to the beginning of the PHP file you want to protect. This manual step ensures that the protection is explicit and works on any server environment. For a complete step-by-step guide, please see our documentation: [How to Protect Non-WordPress Folders](https://advaipbl.com/edge-firewall-mode/).

= What are HTTP Security Headers and why do I need them? =
HTTP Security Headers are instructions sent by your website to the visitor's browser. They tell the browser how to behave to prevent specific types of attacks.
*   **HSTS:** Forces the browser to use a secure HTTPS connection.
*   **X-Frame-Options:** Prevents other sites from embedding your site in an iframe (Clickjacking protection).
*   **X-Content-Type-Options:** Prevents the browser from "guessing" the file type (MIME sniffing protection).
*   **Permissions-Policy:** Controls which features (camera, mic, etc.) legitimate sites can use.
You can configure all of these (and more!) in `Security > Settings > Security Headers`.

= What does the "Username Blocking" feature do? =
It allows you to create aggressive, targeted rules to block login attempts based on the username provided. For example, if you know you never use the username "admin", you can create a rule: **IF Username IS "admin" THEN Block**. This stops brute-force attacks instantly before they can even guess a password.

= Why was the "Direct File Access" warning added for the loader file? =
We improved our security compliance checks. The `advaipbl-loader.php` file is a special file designed to run outside of WordPress in "Edge Mode". We added a specific security check to ensure it can only be run via the `auto_prepend_file` mechanism and cannot be accessed directly by a browser, further hardening the plugin against probing.


== Screenshots ==

1. The new Security Dashboard with real-time charts and a Live Attack Map.
2. Modern and intuitive two-level navigation system for easy access to all features.
3. The main Settings page to configure all protection modules like WAF and Rate Limiting.
4. Powerful Web Application Firewall (WAF) with recommended rules.
5. Block entire networks with ASN Blocking, powered by the Spamhaus list.
6. Detailed Blocked IPs table with the "View Map" modal in action.
7. Country Blocking (Geoblocking) and Geo-Challenge with user-friendly selectors and smart warnings.
8. Unified Security Log with a powerful filter to analyze all attack events.
9. Active User Session Management to monitor and terminate logged-in users.
10. Full WP-CLI support documentation, accessible from the "About" tab.
11. An example of a professional HTML email notification.
12. The new "Trusted Proxies" setting for advanced anti-spoofing protection.
13. IP Trust & Threat Scoring System.
14. Attack Signature Engine (Beta).
15. The new Two-Factor Authentication (2FA) setup section in the user profile.
16. The 2FA Management tab for administrators, showing user status and reset actions.
17. The 2FA prompt on the WordPress login screen after entering a correct password.
18. The new HTTP Security Headers manager.
19. The new AIB Network manager.
20. The new AbuseIPDB Api manager.

== Changelog ==

= 8.9.3 =
*   **NEW FEATURE:** DeepScan for Agencies. Granular control over email notifications. Choose when alerts are sent (e.g., only for critical vulnerabilities) to prevent notification fatigue.
*   **ENHANCEMENT:** Added a dedicated toggle to independently enable or disable the vulnerability (CVE) check.

= 8.9.2 =
*   **NEW FEATURE:** Select2 Country Copy/Paste. You no longer have to manually select 50+ countries repeatedly on multi-site environments. A new hidden tool now lets you copy completely raw 2-letter codes from any source and paste them straight into Geoblocking, GeoChallenge, and Whitelist Login Country elements.
*   **UX:** Added a clear warning to users that having intersecting rules between Geoblocking and Whitelist Login Countries leads to undefined behavior.

= 8.9.1 =
*   **UX ENHANCEMENT:** Grouped "Geoblocking" and "Geo-Challenge" settings into a single, cohesive "Geo-Security" section to improve clarity and reduce confusion. Thank you to the community for this excellent suggestion!
*   **CLARIFICATION:** Reordered geographic protections to display Geoblocking (hard blocks) before Geo-Challenge (soft blocks), ensuring users prioritize stricter regional protections first. 

= 8.9.0 =
*   **NEW MAJOR FEATURE:** AIB Cloud Network V3. We've completely overhauled our Community Defense Network infrastructure. The new API V3 introduces secure, individual API Keys for every connected site, drastically improving synchronization reliability, security telemetry, and overall network stability.
*   **NEW FEATURE:** Whitelist Login Countries. A highly requested feature! You can now explicitly select which countries are allowed to access your WordPress login page (`wp-login.php`) and XML-RPC, automatically blocking all other nations.
*   **ENHANCEMENT:** Upgraded the "Verify Connection" UI for the Cloud Network to provide instant, inline diagnostic feedback (success/error) without page reloads.
*   **CRITICAL FIX:** Resolved an issue where verifying an API key could trigger local 404 block rules due to an incorrect HTTP request method (POST instead of GET).
*   **ROBUSTNESS:** Improved plugin uninstallation logic. When using the "Delete All Data" option, the plugin now seamlessly unregisters the local API Key from the Central Server to keep your account clean for future reinstallations.
*   **ROBUSTNESS:** Prevented the automatic AIB Network protection list from getting stuck on "Downloading..." if an API key fails to generate due to rate limiting on a fresh install.

= 8.8.9 =
*   **SECURITY UPDATE:** Fixed an issue where the "Export Template" feature was inadvertently including sensitive API keys (`cf_api_token`, `cf_zone_id`, `abuseipdb_api_key`) in the generated JSON. Templates are now completely clean of private tokens.
*   **MAINTENANCE:** Cleaned up excessive developer comments in the frontend JS inclusion logic for better code readability.
*   **MAINTENANCE:** Analyzed and ensured that the background Cloudflare Sync task (`advaipbl_cloudflare_sync_event`) schedules properly.

== Upgrade Notice ==

= 8.9.3 =
**NEW AGENCY FEATURES:** Introducing "DeepScan for Agencies". Gain granular control over vulnerability scans and email reports to eliminate notification fatigue.

= 8.9.2 =
**NEW FEATURE UPDATE:** Introducing a seamless way to duplicate your 50+ country configurations! Update to 8.9.2 to instantly access the new Select2 Country Copy/Paste logic tool within the advanced Geoblocking features.

= 8.9.1 =
**MINOR UPDATE:** A quick User Experience (UX) update that reorganizes the geographic security settings into a unified "Geo-Security" section, making configuration much more intuitive.

= 8.9.0 =
**MAJOR UPDATE:** This release launches the AIB Cloud Network V3 and the powerful "Whitelist Login Countries" feature. Update immediately to connect to the new, more secure threat intelligence network infrastructure and take absolute control over your login page access.