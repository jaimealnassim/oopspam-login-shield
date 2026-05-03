# OOPSpam Login Shield

> An **unofficial** connector plugin by [Nahnu Plugins](https://nahnuplugins.com/) that adds login-page protection to WordPress using the [OOPSpam](https://www.oopspam.com/) API.

WordPress out of the box has no spam or bot protection on `wp-login.php`. The official [OOPSpam Anti-Spam](https://wordpress.org/plugins/oopspam-anti-spam/) plugin protects registration but not login. This plugin closes that gap.

It is **not affiliated with or endorsed by OOPSpam**. It is a community-built integration that calls OOPSpam's documented public API.

## Features

- Altcha-style verification checkbox on the WordPress login, registration, and lost-password forms
- AJAX pre-flight check against OOPSpam at page load (blocks bots before they see the password field)
- Server-side re-validation at submission with the actual username or email, before WordPress checks the password
- Optional limit-login-attempts module with rolling-window lockouts and escalation
- Optional honeypot login list: list usernames or emails (with wildcard `admin@*` patterns) that real users would never type, and any IP that submits one is auto-blocked for 24 hours
- Login Log tab with full attempt history (IP, username/email, timestamp, result) and one-click lock release
- Friendly "locked" notice replaces the login form for IPs in lockout
- Diagnostic panel and one-click "Reactivate logging" for recovery from install issues
- All blocked logins logged to OOPSpam's standard admin entries table for review

## Requirements

- WordPress 5.5 or higher
- PHP 8.1 or higher
- The official [OOPSpam Anti-Spam](https://wordpress.org/plugins/oopspam-anti-spam/) plugin (active and configured with an API key)
- An OOPSpam account (free tier or paid)

## Installation

1. Install and activate the [OOPSpam Anti-Spam](https://wordpress.org/plugins/oopspam-anti-spam/) plugin first.
2. Add your OOPSpam API key on the OOPSpam settings page.
3. Download the [latest release zip](https://github.com/jaimealnassim/oopspam-login-shield/releases) of this plugin.
4. Upload it via Plugins > Add New > Upload Plugin, or drop the unzipped folder into `wp-content/plugins/`.
5. Activate it.
6. Go to **Settings > Login Shield** to configure protection.

## How it works

When a visitor lands on `wp-login.php`:

1. The widget loads and immediately fires an AJAX request to your server.
2. Your server calls OOPSpam's `oopspam_check_spam` API with just the visitor's IP.
3. If OOPSpam says the IP looks fine, your server issues an HMAC-signed, IP-bound, single-use token (20-minute lifetime). The widget shows a green checkmark.
4. When the visitor submits the form, your server validates the token (signature, expiry, IP binding, single-use) and runs a second OOPSpam check, this time including the actual username or email so reputation rules can fire.
5. If anything fails, the login is blocked with a friendly message. If everything passes, the request continues to WordPress's normal password check.

The optional limit-login-attempts module hooks `wp_login_failed` and `wp_authenticate_user` (the second one as a backup, for plugins that intercept the auth flow). Once an IP exceeds the configured threshold, a lockout is set in a WordPress option (durable, not a transient that can be evicted by an object cache mid-window). Future requests from that IP see a styled lockout page with the time remaining instead of the login form.

## Configuration

Settings live at **Settings > Login Shield** with three tabs:

- **Settings**: enable/disable protection, choose which forms to protect, configure verification mode (auto-verify on load, or click-the-checkbox), set lockout thresholds.
- **Login Log**: see the diagnostic panel, active lockouts, and full attempt history. Includes a "Reactivate logging" button if anything is broken.
- **About**: links to OOPSpam resources, plugin info, data retention policy, credits.

## Hooks

For developers who want to extend the plugin:

| Hook | Type | Description |
| --- | --- | --- |
| `oopspam_ls_login_blocked` | action | Fires when a login is blocked by OOPSpam. Args: `$username, $ip, $result`. |
| `oopspam_ls_blocked_preflight` | action | Fires when a page-load check is rejected. Args: `$result, $ip`. |
| `oopspam_ls_lla_lockout` | action | Fires when an IP is locked out. Args: `$ip, $username, $expires, $failed_count`. |
| `oopspam_ls_lla_honeypot_trip` | action | Fires when an IP is auto-locked because the submitted login matched a honeypot entry. Args: `$ip, $username, $expires`. |
| `oopspam_ls_lla_bypass` | filter | Return `true` to bypass lockout enforcement (e.g. office IP allowlist). Default: `false`. |
| `oopspam_ls_lla_log_retention_days` | filter | Change the 30-day log retention window. |
| `oopspam_ls_enforce_ip_binding` | filter | Set to `false` to disable IP binding on tokens (proxy-heavy environments). Default: `true`. |

Example:

```php
add_filter( 'oopspam_ls_lla_bypass', function( $bypass ) {
    $office_ips = array( '203.0.113.5', '203.0.113.6' );
    return in_array( $_SERVER['REMOTE_ADDR'] ?? '', $office_ips, true );
} );
```

## Privacy and data retention

Login attempts (IP address, submitted username or email, success or failure, timestamp) are stored in your own WordPress database. They are kept for 30 days and deleted automatically by a daily cron job. Nothing is sent to a third party for the limit-login-attempts feature; this data never leaves your site.

The verification widget does send the visitor's IP and (on submit) the submitted username or email to OOPSpam's API for analysis. OOPSpam's data handling is governed by their own privacy policy.

You can clear the entire log at any time from the Login Log tab. The retention period can be customized via the `oopspam_ls_lla_log_retention_days` filter if you need a longer or shorter window.

## Why a connector plugin and not a fork?

The official OOPSpam plugin is excellent and actively maintained. There is no reason to fork it. By staying as a thin connector, this plugin:

- Uses your existing OOPSpam API key (no separate signup, no separate billing)
- Inherits future improvements to OOPSpam automatically
- Writes blocked logins to OOPSpam's standard admin entries table, so you review everything in one place
- Stays small enough that someone reading the source can audit it in an afternoon

If OOPSpam adds login protection to their core plugin in a future release (which they have hinted they may), this plugin's approach will continue to work as a complementary layer with token verification on top.

## Why not just use a dedicated brute-force plugin?

You probably should, if all you need is brute-force protection. The limit-login-attempts module here is intentionally minimal: IP-based lockouts, an audit log, and manual unlock. If you need allowlists, country blocks, GDPR pseudonymization, or cluster sync, install [Limit Login Attempts Reloaded](https://wordpress.org/plugins/limit-login-attempts-reloaded/) or [WP Limit Login Attempts](https://wordpress.org/plugins/wp-limit-login-attempts/). This plugin includes basic limit-login-attempts as a convenience for sites that want one less plugin to manage.

The complementary value of this plugin is the OOPSpam-powered widget, not the limit-login-attempts feature. Treat that feature as a bonus.

## Credits

OOPSpam and the OOPSpam Anti-Spam plugin are products of [OOPSpam](https://www.oopspam.com/). All credit for the underlying spam-detection capability goes to them. This plugin merely extends their public API.

The widget UX is inspired by [Altcha](https://altcha.org/)'s checkbox-style verification.

This plugin is built and maintained by [Nahnu Plugins](https://nahnuplugins.com/).

## License

GPL v2 or later. See the plugin header for details.

## Links

- [Nahnu Plugins](https://nahnuplugins.com/)
- [OOPSpam website](https://www.oopspam.com/)
- [OOPSpam Anti-Spam plugin (WordPress.org)](https://wordpress.org/plugins/oopspam-anti-spam/)
- [OOPSpam API documentation](https://www.oopspam.com/docs/api)
- [Report a bug or request a feature](https://github.com/jaimealnassim/oopspam-login-shield/issues)
