=== OOPSpam Login Shield ===
Contributors: nahnuplugins
Tags: login, security, brute force, spam, oopspam
Requires at least: 5.5
Tested up to: 6.5
Requires PHP: 8.1
Stable tag: 1.0.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Adds a checkbox-style verification widget and brute-force protection to the WordPress login page. Powered by the OOPSpam API.

== Description ==

OOPSpam Login Shield is an **unofficial connector plugin by Nahnu Plugins** that extends the official OOPSpam Anti-Spam plugin with login-page protection. WordPress out of the box has no spam or bot protection on `wp-login.php`, and although the official OOPSpam plugin can also protect login as of version 1.2.68, this connector adds a verification widget, a brute-force lockout module, a honeypot list, country blocklist with quick-pick UI, JavaScript-required gating, and an audit log on top.

It is not affiliated with or endorsed by OOPSpam. It is a community-built integration that calls OOPSpam's documented public API to do the actual spam and bot detection.

= What it does =

* **Verification widget.** Renders a checkbox-style verification widget on the WordPress login, registration, and lost-password forms. Two modes: manual click (default, reCAPTCHA-style) or auto-verify on page load (Altcha-style).
* **Pre-flight bot check.** AJAX-triggers an IP-only OOPSpam check as soon as the form loads, so reputation-flagged bots are rejected before they ever see the password field.
* **Server-side re-validation at submission.** Verifies an HMAC-signed, IP-bound, single-use token (20-minute lifetime), then runs a second OOPSpam check with the actual username or email. Blocked attempts are logged to OOPSpam's standard admin entries table for review alongside everything else they catch.
* **Limit login attempts.** Optional module: lock out IPs after too many failed attempts in a rolling window, with escalation to a longer block on repeated abuse. IPs in active lockout see a styled "locked" notice in place of the login form.
* **Honeypot login list.** Configure usernames and emails (with `admin@*` wildcard support) that real users would never type. Any IP that submits one is blocked immediately for 24 hours, no warning, no threshold counting. Default list includes common bot targets like `admin`, `administrator`, `root`, `test`, `webmaster`, plus wildcard email patterns.
* **Connector-specific rules.** Apply stricter spam rules at login than the rest of the site uses. For each of VPN blocking, datacenter blocking, temp-email blocking, and country blocklist, choose Inherit (use OOPSpam's sitewide setting) or Override (always block at login regardless). Useful for sites that want to allow VPN users to browse but require admin and customer logins from clean residential IPs.
* **Country blocklist with visual picker.** Click region toggle buttons to add or remove whole groups (China & Russia, Africa, Europe, North America, South America, MENA, Asia, Oceania). Click again to remove. Or click individual country chips. Live status shows what's currently selected.
* **Coordinate with OOPSpam.** When OOPSpam Anti-Spam 1.2.68+ is also running login protection, this plugin auto-detects and steps aside on the duplicate API call to avoid double quota burn and double false-positive risk. Optional "Take over login protection" toggle suppresses OOPSpam's login layer entirely so this plugin is the sole authority.
* **Require JavaScript.** Independent setting: reject any login, registration, or lost-password submission that didn't come from a JS-running browser. Filters out a large slice of automated traffic before the password check.
* **Login Log tab.** Paginated attempt history showing IP, username or email, timestamp, and result. Active-lockout panel with one-click Release Lock buttons. Diagnostic panel that surfaces install issues and offers a "Reactivate logging" button for one-click recovery.
* **About tab.** Resource links to OOPSpam, this plugin's repository, and a clear unofficial-plugin disclosure.

= How it works =

When a visitor lands on `wp-login.php`, the widget loads and immediately fires an AJAX request to your server. Your server calls OOPSpam's `oopspam_check_spam` API with just the visitor's IP. If OOPSpam says the IP looks fine, your server issues an HMAC-signed, IP-bound, single-use token (20-minute lifetime) which is stashed in a hidden form field. The widget shows a green checkmark.

When the visitor submits the form, your server validates the token (signature, expiry, IP binding, single-use) and runs a second OOPSpam check, this time including the actual username or email so reputation rules can fire. If anything fails, the login is blocked with a friendly message. If everything passes, the request continues to WordPress's normal password check.

The optional limit-login-attempts module hooks `wp_login_failed` and `wp_authenticate_user` (the second one as a backup, for plugins that intercept the auth flow). Once an IP exceeds the configured threshold, a lockout is set in a WordPress option (durable, not a transient that can be evicted by an object cache mid-window). Future requests from that IP see a styled lockout page with the time remaining instead of the login form.

When any connector-specific rule is in Override mode, this plugin calls the OOPSpam API directly (reusing your stored API key) with explicit per-call parameters. Rules in Inherit mode read OOPSpam's own settings, so a single override does not accidentally disable other protections.

= Why use this if I already have the official OOPSpam plugin? =

The official plugin protects forms (comments, contacts, registration, and as of 1.2.68 also login). This plugin adds a verification widget, a configurable limit-login-attempts module, a honeypot list, a JavaScript-required gate, an audit log, country quick-pick, and per-connector rule overrides on top. All of these layer cleanly with the official plugin's protection rather than replacing it.

If you only need basic login protection and OOPSpam's built-in toggle is enough, you don't need this plugin. If you want defense in depth (multi-layered, configurable, with auditability), this fills the gap.

= Why use this instead of a dedicated brute-force plugin? =

You probably should not, if all you need is brute-force protection. The limit-login-attempts module here is intentionally minimal: IP-based lockouts, an audit log, and manual unlock. If you need allowlists, country blocks, GDPR pseudonymization, or cluster sync, install Limit Login Attempts Reloaded or WP Limit Login Attempts. This plugin includes basic limit-login-attempts as a convenience for sites that want one less plugin to manage.

The complementary value of this plugin is the OOPSpam-powered widget, the honeypot, and the connector-specific rules. Treat the limit-login-attempts feature as a bonus.

= Requirements =

* WordPress 5.5 or higher
* PHP 8.1 or higher
* The official OOPSpam Anti-Spam plugin, installed, active, and configured with an API key
* An OOPSpam account (free tier or paid)

If OOPSpam is missing or unconfigured, the widget still renders but the plugin will not validate requests. An admin notice tells you what to fix.

= Privacy and data =

Login attempts (IP address, submitted username or email, success or failure, and timestamp) are stored in your own WordPress database. They are kept for 30 days and then deleted automatically by a daily WordPress cron job. Nothing is sent to a third party for the limit-login-attempts feature; this data never leaves your site.

The verification widget does send the visitor's IP and (on submit) the submitted username or email to OOPSpam's API for analysis. OOPSpam's data handling is governed by their own privacy policy.

You can clear the entire log at any time from the Login Log tab. The retention period can be customized via the `oopspam_ls_lla_log_retention_days` filter if you need a longer or shorter window.

= Credits =

OOPSpam and the OOPSpam Anti-Spam plugin are products of OOPSpam. All credit for the underlying spam-detection capability goes to them; this plugin merely extends their public API. The widget UX is inspired by Altcha's checkbox-style verification.

This plugin is built and maintained by [Nahnu Plugins](https://nahnuplugins.com/). It is not affiliated with or endorsed by OOPSpam.

== Installation ==

1. Install and activate the official [OOPSpam Anti-Spam](https://wordpress.org/plugins/oopspam-anti-spam/) plugin first.
2. Add your OOPSpam API key on the OOPSpam settings page.
3. Upload the OOPSpam Login Shield zip via Plugins > Add New > Upload Plugin, or drop the unzipped folder into `wp-content/plugins/`.
4. Activate the plugin.
5. Go to Settings > Login Shield to configure protection rules.

The widget appears on `wp-login.php` immediately. Test it by opening your login page in a private window.

== Frequently Asked Questions ==

= I do not see anything in the Login Log tab even after failed login attempts. =

Open the Login Log tab and look at the diagnostics panel. If anything shows a red X, click "Reactivate logging" to re-run the install routine. This recreates the log table if it is missing and re-registers the recording hooks. Then attempt a wrong-password login from another browser to confirm logging is working.

= I updated to OOPSpam Anti-Spam 1.2.68 and now logins are getting blocked even with correct passwords. =

OOPSpam 1.2.68 added its own login protection. When both layers run on the same login attempt, the doubled API quota and doubled false-positive risk can cause legitimate users to be blocked. Go to Settings > Login Shield and check the "Take over login protection" box, or disable OOPSpam's "Spam protection on the WordPress login form" toggle on their settings page. Either approach makes one plugin the sole authority on login.

= Does this work with two-factor authentication plugins? =

Yes. The plugin's checks run before and after WordPress's password validation, but never interfere with valid logins. 2FA plugins continue to work normally for users who pass our checks.

= Does this work with custom login URL plugins? =

Yes, as long as the custom login form still uses standard WordPress hooks (`login_form`, `authenticate`, etc). Most popular custom-login plugins do.

= Will I get locked out by my own plugin? =

The limit-login-attempts feature only counts failed attempts, and it is off by default. You would need to enable it explicitly and then fail your own password the configured number of times to lock yourself out. Even then, you can manually release the lock from the Login Log tab as long as you can reach `/wp-admin/` from a different IP.

If you enabled the honeypot feature and added your own admin email or username to it by mistake, you can lock yourself out on a single failed login. Review the honeypot list before enabling.

If you enabled "Require JavaScript" and your own browser has JavaScript disabled, you will not be able to log in. Disable the setting via WP-CLI (`wp option get oopspam_ls_settings`, edit, `wp option update`) or by uploading a `wp-config.php` snippet that filters the option.

= I run my site behind Cloudflare or another CDN. Will the IP be detected correctly? =

Yes. The plugin uses the same IP-detection logic as the official OOPSpam plugin, which respects standard proxy headers like CF-Connecting-IP.

= My site only allows email login but bots keep trying usernames like 'admin'. How do I block them faster? =

Enable the honeypot feature on the Settings tab and add the usernames bots are trying. Any IP that submits one will be blocked instantly for 24 hours. The default list already includes common bot targets (`admin`, `administrator`, `root`, `test`, plus wildcard email patterns like `admin@*` that catch attempts at `admin@your-domain.com`).

= Can I have stricter rules at login than for the rest of my site? =

Yes. The Connector-specific rules section lets you set Inherit or Override for each of: block VPN, block datacenter/cloud IPs, block temp emails, and country blocklist. Inherit uses OOPSpam's sitewide setting; Override forces the rule on at login regardless. Useful for sites that allow international or VPN users to browse content but require admin and customer logins from clean residential IPs in approved regions.

= Does this protect XML-RPC and REST API logins? =

The verification widget protects browser-based login forms only. XML-RPC and REST authentication are intentionally excluded because the widget cannot render in those contexts. The limit-login-attempts module does count failed XML-RPC logins toward lockout thresholds, since `wp_login_failed` fires there too.

= Can I extend the plugin with custom logic? =

Yes. Several action and filter hooks are available:

* `oopspam_ls_login_blocked` action: fires when a login is blocked by OOPSpam. Args: `$username, $ip, $result`.
* `oopspam_ls_blocked_preflight` action: fires when a page-load check is rejected. Args: `$result, $ip`.
* `oopspam_ls_lla_lockout` action: fires when an IP is locked out. Args: `$ip, $username, $expires, $failed_count`.
* `oopspam_ls_lla_honeypot_trip` action: fires when an IP is auto-locked because the submitted login matched a honeypot entry. Args: `$ip, $username, $expires`.
* `oopspam_ls_lla_bypass` filter: return true to bypass lockout enforcement (useful for office IP allowlists).
* `oopspam_ls_lla_log_retention_days` filter: change the 30-day log-retention window.
* `oopspam_ls_enforce_ip_binding` filter: disable IP binding on tokens (proxy-heavy environments).

== Changelog ==

= 1.0.4 =
* Country region buttons are now toggles. Click "+ Africa" to add all African countries; the button label flips to "− Africa" and turns blue. Click again to remove them all. Same for every region.
* Region buttons show "is-active" blue tint when their entire region is currently selected, so you can scan all eight regions at a glance and see which groups are in.
* Removed the duplicate "− China & Russia" button (toggle behavior makes it unnecessary).

= 1.0.3 =
* Critical picker CSS is now inlined into the page response via `wp_add_inline_style`, so the country picker renders correctly even when the external CSS file is stale-cached on aggressive mobile browsers.
* Chip styling no longer depends on flexbox; uses block-level layout with explicit margins so chips render legibly even if advanced CSS features are stripped.
* Country chip code and name now separated by a non-breaking space in the markup, in addition to CSS spacing, as a guaranteed visual separator.

= 1.0.2 =
* Country blocklist now has a visual picker with clickable country chips and one-click region buttons (China & Russia, Africa, Europe, North America, South America, MENA, Asia, Oceania).
* Inherit-vs-override modes for connector-specific rules (block VPN, block datacenter, block temp email, country list). Inherit reads OOPSpam plugin settings; override forces the rule on at login regardless.
* New "Require JavaScript" setting blocks form submissions from clients that don't run JS (filters out most bots before any password check).
* Default verification mode is now manual click (Altcha-style auto-verify is still available as an option).
* "Take over login protection" setting forces OOPSpam Anti-Spam 1.2.68+'s built-in login toggle off at read-time, so this plugin can be the sole authority on login when both are installed.
* Auto-detection: when OOPSpam's native login protection is on, this plugin's duplicate OOPSpam call at submit time is skipped automatically to avoid double API quota and double false-positive risk.
* Fixed: token validation now caches results within a single request so multi-pass authenticate filters don't trip the single-use replay guard. (Was causing valid logins to fail with "Verification token already used" after OOPSpam 1.2.68's auth-flow changes.)
* Fixed: country blocklist inherit-mode now correctly handles OOPSpam's array-typed `oopspam_countryblocklist` option (was previously displaying as the literal text "Array").

= 1.0.1 =
* Initial public release.
* Altcha-style verification widget on login, registration, and lost-password forms.
* Calls OOPSpam's documented public API (`oopspam_check_spam`) with fallback to the internal helper for older OOPSpam versions.
* Optional limit-login-attempts module with rolling-window lockouts, audit log, and manual release.
* Optional honeypot login list with wildcard email matching, for instant 24-hour IP blocks.
* Diagnostic panel and one-click "Reactivate logging" for recovery from install issues.
* Login Log tab with paginated attempt history and active-lockout management.
* About tab with OOPSpam reference links and clear unofficial-plugin disclosure.

== Upgrade Notice ==

= 1.0.4 =
Region buttons now toggle (click to add, click again to remove). Removes redundant "− China & Russia" button.

= 1.0.3 =
Cache-resilient picker styles via inlined CSS. Picker chips render correctly on mobile browsers that aggressively cache external assets.

= 1.0.2 =
Country blocklist picker with region buttons. Connector-rule inherit/override modes. Require JavaScript setting. Take-over-login coordination with OOPSpam 1.2.68. Token replay fix for multi-pass auth filters.

= 1.0.1 =
Initial public release.
