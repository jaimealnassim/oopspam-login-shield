# OOPSpam Login Shield

> An **unofficial** connector plugin by [Nahnu Plugins](https://nahnuplugins.com/) that adds login-page protection to WordPress using the [OOPSpam](https://www.oopspam.com/) API.

WordPress out of the box has no spam or bot protection on `wp-login.php`. The official [OOPSpam Anti-Spam](https://wordpress.org/plugins/oopspam-anti-spam/) plugin can also protect login as of version 1.2.68, but if you want a verification widget, brute-force lockouts, a honeypot list, country quick-pick, JavaScript gating, and an audit log layered on top, this is the plugin.

It is **not affiliated with or endorsed by OOPSpam**. It is a community-built integration that calls OOPSpam's documented public API.

## Features

- **Verification widget** on the WordPress login, registration, and lost-password forms (manual click or auto-verify on load).
- **Pre-flight bot check** via AJAX as soon as the form loads, so reputation-flagged bots are rejected before they see the password field.
- **Server-side re-validation at submission** with token verification (HMAC-signed, IP-bound, single-use, 20-minute lifetime) plus a second OOPSpam check using the actual username or email.
- **Optional limit-login-attempts module** with rolling-window lockouts and escalation to a longer block on repeated abuse. Locked IPs see a styled "locked" notice in place of the login form.
- **Honeypot login list.** Configure usernames and emails (with `admin@*` wildcard support) that real users would never type. Any IP that submits one is blocked instantly for 24 hours.
- **Connector-specific rules.** For each of VPN blocking, datacenter blocking, temp-email blocking, and country blocklist, choose Inherit (use OOPSpam's sitewide setting) or Override (always block at login regardless). Lets you have stricter login rules than site-wide rules.
- **Country blocklist with visual picker.** Click region toggle buttons to add or remove whole groups (China & Russia, Africa, Europe, North America, South America, MENA, Asia, Oceania). Click again to remove. Or click individual country chips. Live status shows what is currently selected.
- **Coordinate with OOPSpam.** Auto-detects when OOPSpam Anti-Spam 1.2.68+ is running its own login protection and steps aside on the duplicate API call. Optional "Take over login protection" toggle suppresses OOPSpam's login layer entirely so this plugin is the sole authority.
- **Require JavaScript.** Independent setting that rejects any login, registration, or lost-password submission from a non-JS client. Filters out a large slice of automated traffic before the password check.
- **Login Log tab** with paginated attempt history (IP, username/email, timestamp, result), active-lockout panel with one-click Release Lock buttons, and a diagnostic panel that surfaces install issues with a one-click "Reactivate logging" recovery button.
- **About tab** with OOPSpam resource links and clear unofficial-plugin disclosure.

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

When any connector-specific rule is in Override mode, this plugin calls the OOPSpam API directly (reusing your stored API key) with explicit per-call parameters. Rules in Inherit mode read OOPSpam's own settings, so a single override does not accidentally disable other protections.

## Configuration

Settings live at **Settings > Login Shield** with three tabs:

- **Settings**: enable/disable protection, choose which forms to protect, configure verification mode, set lockout thresholds, configure honeypot, configure connector-specific rules with Inherit/Override modes, country picker, JavaScript-required toggle, OOPSpam coordination.
- **Login Log**: diagnostic panel, active lockouts, and full attempt history. Includes a "Reactivate logging" button if anything is broken.
- **About**: links to OOPSpam resources, plugin info, data retention policy, credits.

## Country picker

The country blocklist UI is a region-based toggle picker. Click "+ Africa" and all African countries get added; the button flips to "− Africa" with a blue tint. Click again to remove them all. Same for the other seven regions: China & Russia, Europe, North America, South America, MENA, Asia, Oceania. Clicking a region button when all its countries are already selected removes them; clicking when only some are selected fills in the missing ones.

Below the region buttons, a scrollable grid shows individual country chips. Click any chip to toggle that single country. The textarea at the bottom is the source of truth and stays in two-way sync with the chips, so power users can paste a comma-separated list directly.

The picker only appears when the country blocklist mode is set to "Use a custom list at login." When the mode is "Use OOPSpam plugin setting," the picker hides itself because it would have no effect.

## Connector-specific rules

Four rules can be set independently to Inherit (use OOPSpam's sitewide setting) or Override (force on at login):

| Rule | Inherit reads from | Override forces |
| --- | --- | --- |
| Block VPN | `oopspamantispam_ipfiltering_settings.oopspam_block_vpns` | VPN blocking on at login regardless |
| Block datacenter/cloud IPs | `oopspamantispam_ipfiltering_settings.oopspam_block_cloud_providers` | Datacenter blocking on at login regardless |
| Block temporary email | `oopspamantispam_settings.oopspam_block_temp_email` | Temp-email blocking on at login regardless |
| Country blocklist | `oopspam_countryblocklist` option | Custom list defined in this plugin's settings |

When all four are set to Inherit, the standard OOPSpam wrapper is used. When any one is in Override mode, the plugin calls the OOPSpam API directly with explicit per-call parameters. Either way, blocked attempts are logged to OOPSpam's standard Spam/Ham Entries tables under a stable form ID.

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

Example: bypass lockouts for office IPs.

```php
add_filter( 'oopspam_ls_lla_bypass', function( $bypass ) {
    $office_ips = array( '203.0.113.5', '203.0.113.6' );
    return in_array( $_SERVER['REMOTE_ADDR'] ?? '', $office_ips, true );
} );
```

Example: shorter log retention for GDPR.

```php
add_filter( 'oopspam_ls_lla_log_retention_days', function() { return 7; } );
```

## Privacy and data retention

Login attempts (IP address, submitted username or email, success or failure, timestamp) are stored in your own WordPress database. They are kept for 30 days and deleted automatically by a daily cron job. Nothing is sent to a third party for the limit-login-attempts feature; this data never leaves your site.

The verification widget does send the visitor's IP and (on submit) the submitted username or email to OOPSpam's API for analysis. OOPSpam's data handling is governed by their own privacy policy.

You can clear the entire log at any time from the Login Log tab. The retention period can be customized via the `oopspam_ls_lla_log_retention_days` filter if you need a longer or shorter window.

## Why a connector plugin and not a fork?

The official OOPSpam plugin is excellent and actively maintained. There is no reason to fork it. By staying as a thin connector, this plugin:

- Uses your existing OOPSpam API key (no separate signup, no separate billing).
- Inherits future improvements to OOPSpam automatically.
- Writes blocked logins to OOPSpam's standard admin entries table, so you review everything in one place.
- Stays small enough that someone reading the source can audit it in an afternoon.

OOPSpam added their own login protection in 1.2.68, after this plugin's first public release. Rather than competing, this connector now coordinates with theirs: when both are active, our plugin auto-detects and skips the duplicate API call, and an optional "Take over login protection" toggle lets admins choose which layer is in charge. The verification widget, limit-login-attempts module, honeypot, country picker, JavaScript gate, and audit log all stay active either way.

## Why not just use a dedicated brute-force plugin?

You probably should, if all you need is brute-force protection. The limit-login-attempts module here is intentionally minimal: IP-based lockouts, an audit log, and manual unlock. If you need allowlists, country blocks, GDPR pseudonymization, or cluster sync, install [Limit Login Attempts Reloaded](https://wordpress.org/plugins/limit-login-attempts-reloaded/) or [WP Limit Login Attempts](https://wordpress.org/plugins/wp-limit-login-attempts/).

The complementary value of this plugin is the OOPSpam-powered widget, the honeypot, and the connector-specific rules. The limit-login-attempts module is a convenience for sites that want one less plugin to manage.

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
