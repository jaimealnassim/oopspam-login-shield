=== OOPSpam Login Shield ===
Contributors: nahnuplugins
Tags: login, security, brute force, spam, oopspam
Requires at least: 5.5
Tested up to: 6.5
Requires PHP: 8.1
Stable tag: 1.0.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Adds a checkbox-style verification widget and brute-force protection to the WordPress login page. Powered by the OOPSpam API.

== Description ==

OOPSpam Login Shield is an **unofficial connector plugin by Nahnu Plugins** that extends the official OOPSpam Anti-Spam plugin with login-page protection. WordPress out of the box has zero spam or bot protection on `wp-login.php`, and the official OOPSpam plugin protects registration but not login. This plugin closes that gap.

It is not affiliated with or endorsed by OOPSpam. It is a community-built integration that calls OOPSpam's documented public API to do the actual spam and bot detection.

= What it does =

* Renders an Altcha-style verification checkbox on the WordPress login, registration, and lost-password forms.
* Pre-flights an IP-only OOPSpam check via AJAX as soon as the form loads, so bots are blocked before they ever see a password field.
* Re-checks the request server-side at submission with the actual username or email, before WordPress validates the password. Blocked logins are written to OOPSpam's standard admin entries table for review.
* Adds an optional limit-login-attempts module that locks out IPs after too many failed attempts, with a configurable rolling window and escalation to a longer block on repeated abuse.
* Optional honeypot login list: any IP that submits a configured username or email (e.g. `admin`, `admin@*`) is blocked immediately for 24 hours, no warning. Useful when bots try bare usernames on email-only login forms.
* Provides a Login Log tab showing every attempt with IP, username or email, timestamp, and result. Includes a Release Lock button for manually clearing lockouts.
* Replaces the login form with a friendly "locked" notice for IPs currently in lockout, instead of letting them keep trying.

= How it works =

When a visitor lands on `wp-login.php`, the widget loads and immediately fires an AJAX request to your server. Your server calls OOPSpam's `oopspam_check_spam` API with just the visitor's IP. If OOPSpam says the IP looks fine, your server issues an HMAC-signed, IP-bound, single-use token (20-minute lifetime) which is stashed in a hidden form field. The widget shows a green checkmark.

When the visitor submits the form, your server validates the token (signature, expiry, IP binding, single-use) and runs a second OOPSpam check, this time including the actual username or email so reputation rules can fire. If anything fails, the login is blocked with a friendly message. If everything passes, the request continues to WordPress's normal password check.

The optional limit-login-attempts module hooks `wp_login_failed` and records every attempt to a custom log table. Once an IP exceeds the configured threshold, a lockout is set in a WordPress option (durable, not a transient that can be evicted by an object cache mid-window). Future requests from that IP see a styled lockout page with the time remaining instead of the login form.

= Why use this if I already have the official OOPSpam plugin? =

The official plugin protects forms (comments, contacts, registration). It does not protect `wp-login.php`. This plugin adds that one missing piece using the same API key and the same OOPSpam infrastructure you already trust.

= Why use this instead of a dedicated brute-force plugin? =

You probably should not, if all you need is brute-force protection. The limit-login-attempts module here is intentionally minimal: IP-based lockouts, an audit log, and manual unlock. If you need allowlists, country blocks, GDPR pseudonymization, or cluster sync, install Limit Login Attempts Reloaded or WP Limit Login Attempts. This plugin includes basic limit-login-attempts as a convenience for sites that want one less plugin to manage.

= Requirements =

* WordPress 5.5 or higher
* PHP 8.1 or higher
* The official OOPSpam Anti-Spam plugin, installed, active, and configured with an API key
* An OOPSpam account (free tier or paid)

If OOPSpam is missing or unconfigured, the widget still renders but the plugin will not validate requests. An admin notice tells you what to fix.

= Privacy and data =

Login attempts (IP address, submitted username or email, success or failure, and timestamp) are stored in your own WordPress database. They are kept for 30 days and then deleted automatically by a daily WordPress cron job. Nothing is sent to a third party for the limit-login-attempts feature; this data never leaves your site.

The verification widget does send the visitor's IP and (on submit) the submitted username or email to OOPSpam's API for analysis. OOPSpam's data handling is governed by their own privacy policy.

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

= Does this work with two-factor authentication plugins? =

Yes. The plugin's checks run before and after WordPress's password validation, but never interfere with valid logins. 2FA plugins continue to work normally for users who pass our checks.

= Does this work with custom login URL plugins? =

Yes, as long as the custom login form still uses standard WordPress hooks (`login_form`, `authenticate`, etc). Most popular custom-login plugins do.

= Will I get locked out by my own plugin? =

The limit-login-attempts feature only counts failed attempts, and it is off by default. You would need to enable it explicitly and then fail your own password the configured number of times to lock yourself out. Even then, you can manually release the lock from the Login Log tab as long as you can reach `/wp-admin/` from a different IP.

= I run my site behind Cloudflare or another CDN. Will the IP be detected correctly? =

Yes. The plugin uses the same IP-detection logic as the official OOPSpam plugin, which respects standard proxy headers like CF-Connecting-IP.

= My site only allows email login but bots keep trying usernames like 'admin'. How do I block them faster? =

Enable the honeypot feature on the Settings tab and add the usernames bots are trying. Any IP that submits one will be blocked instantly for 24 hours. The default list already includes common bot targets (`admin`, `administrator`, `root`, `test`, plus wildcard email patterns like `admin@*` that catch attempts at `admin@your-domain.com`).

= Does this protect XML-RPC and REST API logins? =

The verification widget protects browser-based login forms only. XML-RPC and REST authentication are intentionally excluded because the widget cannot render in those contexts. The limit-login-attempts module does count failed XML-RPC logins toward lockout thresholds, since `wp_login_failed` fires there too.

= Can I extend the plugin with custom logic? =

Yes. Several action and filter hooks are available:

* `oopspam_ls_login_blocked` action: fires when a login is blocked by OOPSpam.
* `oopspam_ls_blocked_preflight` action: fires when a page-load check is rejected.
* `oopspam_ls_lla_lockout` action: fires when an IP is locked out.
* `oopspam_ls_lla_bypass` filter: return true to bypass lockout enforcement (useful for office IP allowlists).
* `oopspam_ls_lla_log_retention_days` filter: change the 30-day log-retention window.
* `oopspam_ls_enforce_ip_binding` filter: disable IP binding on tokens (proxy-heavy environments).

== Changelog ==

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

= 1.0.1 =
Initial public release.
