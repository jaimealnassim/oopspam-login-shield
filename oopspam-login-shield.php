<?php
/**
 * Plugin Name: OOPSpam Login Shield
 * Plugin URI: https://nahnuplugins.com/
 * Description: Adds an Altcha-style verification widget to the WordPress login, registration, and lost-password forms. Verifies each request against the OOPSpam API to block bots, credential stuffers, and known-bad IPs.
 * Version: 1.0.2
 * Author: Nahnu Plugins
 * Author URI: https://nahnuplugins.com/
 * Text Domain: oopspam-login-shield
 * Domain Path: /languages
 * Requires at least: 5.5
 * Requires PHP: 8.1
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * Companion to the OOPSpam Anti-Spam plugin (https://wordpress.org/plugins/oopspam-anti-spam/).
 * Requires that plugin to be active and configured with an API key.
 *
 * @package OOPSpam_Login_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/* -----------------------------------------------------------------------
 * PHP version gate.
 *
 * The class files in includes/ use PHP 8.1 syntax (enums, first-class
 * callable syntax, match expressions, typed properties / parameters /
 * returns). On older PHP, parsing those files is a fatal error — so we
 * MUST short-circuit here BEFORE requiring any of them.
 *
 * IMPORTANT: keep this section in PHP 7-compatible syntax. The closure,
 * sprintf, and version_compare calls below all work on PHP 7+.
 * --------------------------------------------------------------------- */
if ( version_compare( PHP_VERSION, '8.1.0', '<' ) ) {
	add_action( 'admin_notices', function () {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		$msg = sprintf(
			/* translators: %s: current PHP version */
			'OOPSpam Login Shield requires PHP 8.1 or higher. You are running PHP %s. Please ask your host to upgrade.',
			PHP_VERSION
		);
		echo '<div class="notice notice-error"><p><strong>' . esc_html( $msg ) . '</strong></p></div>';
	} );
	return;
}

define( 'OOPSPAM_LS_VERSION',   '1.0.2' );
define( 'OOPSPAM_LS_FILE',      __FILE__ );
define( 'OOPSPAM_LS_BASENAME',  plugin_basename( __FILE__ ) );
define( 'OOPSPAM_LS_DIR',       plugin_dir_path( __FILE__ ) );
define( 'OOPSPAM_LS_URL',       plugin_dir_url( __FILE__ ) );
define( 'OOPSPAM_LS_TOKEN_TTL', 20 * MINUTE_IN_SECONDS ); // 20 minutes — security still hard-gated by HMAC + single-use + IP-binding.

/**
 * Default settings.
 *
 * @return array
 */
function oopspam_ls_default_settings() {
	return array(
		'enabled'              => 1,
		'protect_login'        => 1,
		'protect_register'     => 1,
		'protect_lostpassword' => 0,
		'auto_verify'          => 1,
		'spam_message'         => __( 'Your request was blocked as suspicious. If this is a mistake, please contact the site administrator.', 'oopspam-login-shield' ),
		'fail_message'         => __( 'Could not verify your request. Please refresh and try again.', 'oopspam-login-shield' ),

		// When on, programmatically forces OOPSpam Anti-Spam's "WP login
		// protection" toggle to OFF, so our login layer is the only one
		// running (no double API calls, no double false-positive risk).
		// Off by default to avoid surprising admins who deliberately turned
		// theirs on.
		'takeover_login'       => 0,

		// Limit Login Attempts.
		'lla_enabled'          => 0,   // off by default — opt-in feature
		'lla_max_attempts'     => 5,   // failed attempts allowed in the rolling window
		'lla_lockout_minutes'  => 15,  // length of the short lockout
		'lla_max_lockouts'     => 4,   // short lockouts in 24h before escalating
		'lla_long_hours'       => 24,  // length of the long lockout

		// Honeypot logins: any attempt matching these triggers an immediate
		// 24-hour IP lockout (no warning, no second chance). Useful when
		// you've configured the site for email-only login but bots keep
		// trying common usernames anyway.
		'lla_honeypot_enabled' => 0,
		'lla_honeypot_hours'   => 24,
		// Comma- or newline-separated. Username matches are case-insensitive.
		// Email matches support `local@*` to match any domain (catches the
		// "admin@<sitedomain>" pattern).
		'lla_honeypot_logins'  => "admin\nadministrator\nroot\ntest\nwebmaster\nadmin@*\nadministrator@*\nroot@*\nwebmaster@*\ninfo@*",
	);
}

/**
 * Get merged settings with defaults.
 *
 * @return array
 */
function oopspam_ls_get_settings() {
	$opts = get_option( 'oopspam_ls_settings', array() );
	if ( ! is_array( $opts ) ) {
		$opts = array();
	}
	return wp_parse_args( $opts, oopspam_ls_default_settings() );
}

/**
 * Whether the OOPSpam Anti-Spam plugin is active and configured.
 *
 * Accepts either the documented public API (oopspam_check_spam, recommended)
 * or the older internal helper (oopspamantispam_call_OOPSpam) as proof that
 * the parent plugin is callable.
 *
 * @return bool
 */
function oopspam_ls_is_oopspam_ready() {
	$has_callable = function_exists( 'oopspam_check_spam' )
		|| function_exists( 'oopspamantispam_call_OOPSpam' );

	return $has_callable
		&& function_exists( 'oopspamantispam_get_key' )
		&& ! empty( oopspamantispam_get_key() );
}

/**
 * Check whether OOPSpam's own built-in login protection is active.
 *
 * As of OOPSpam Anti-Spam 1.2.68, the parent plugin ships its own
 * wp_authenticate_user filter that runs an OOPSpam check on every login.
 * When that's enabled, our own login-time OOPSpam check is redundant: it
 * burns extra API quota and stacks two independent spam-classifications
 * on the same request, which doubles the chance of a false-positive
 * lockout for legitimate users on edge-case IPs (mobile networks, VPNs).
 *
 * This helper checks two things, in order:
 *
 *   1. The OOPSpam constant, OOPSPAM_IS_WPLOGIN_ACTIVATED. Sites that
 *      configured this in wp-config.php override the option.
 *   2. The plugin option, oopspam_is_wplogin_activated. This is set
 *      from OOPSpam's settings page when the admin enables the
 *      "Spam protection on the WordPress login form" toggle.
 *
 * Returns false on older OOPSpam versions that don't have this feature
 * (so behavior is unchanged for users who haven't updated).
 *
 * @return bool
 */
function oopspam_ls_oopspam_handles_login() {
	// If we're taking over, we suppress their toggle at read-time, so they
	// effectively don't handle login any more.
	$ours = get_option( 'oopspam_ls_settings', array() );
	if ( ! empty( $ours['takeover_login'] ) ) {
		return false;
	}

	// Constant-based override always wins (over both their option and ours).
	if ( defined( 'OOPSPAM_IS_WPLOGIN_ACTIVATED' ) ) {
		return (bool) constant( 'OOPSPAM_IS_WPLOGIN_ACTIVATED' );
	}

	$opts = get_option( 'oopspamantispam_settings' );
	if ( ! is_array( $opts ) ) {
		return false;
	}

	return ! empty( $opts['oopspam_is_wplogin_activated'] )
		&& 1 == $opts['oopspam_is_wplogin_activated'];
}

/**
 * Run an OOPSpam check, preferring the documented public API
 * (oopspam_check_spam) and falling back to the internal helper for
 * users running OOPSpam versions that pre-date it.
 *
 * Normalises both response shapes to:
 *   array( 'Score' => int, 'isSpam' => bool, 'Reason' => string )
 *
 * Notes on $content: the public API uses the internal 'custom' type, which
 * does NOT bypass the parent plugin's optional "messages shorter than 20
 * chars are spam" length filter. Callers should therefore pass a sentinel
 * string longer than 20 characters that also serves as a useful description
 * in the OOPSpam admin entries table (e.g. 'OOPSpam Login Shield: login
 * attempt as "jdoe"').
 *
 * @param string $ip      Submitter IP (already obtained from oopspamantispam_get_ip()).
 * @param string $email   Submitter email, or '' if unknown at this stage.
 * @param string $content Sentinel content string, > 20 chars.
 * @param array  $args {
 *     Optional.
 *     @type bool   $log      Log to Spam/Ham Entries tables. Default true.
 *     @type string $form_id  Identifier shown in admin entry filters. Default 'oopspam-login-shield'.
 *     @type string $raw_data Extra context to log. Default ''.
 * }
 * @return array|null Normalised result, or null if no check was possible.
 */
function oopspam_ls_run_check( $ip, $email, $content, $args = array() ) {
	$args = wp_parse_args(
		$args,
		array(
			'log'      => true,
			'form_id'  => 'oopspam-login-shield',
			'raw_data' => '',
		)
	);

	// Preferred path: the documented public API.
	if ( function_exists( 'oopspam_check_spam' ) ) {
		$result = oopspam_check_spam(
			$ip,
			$email,
			$content,
			array(
				'log'      => (bool) $args['log'],
				'form_id'  => (string) $args['form_id'],
				'raw_data' => (string) $args['raw_data'],
			)
		);

		if ( ! is_array( $result ) || ! isset( $result['Score'] ) ) {
			return null;
		}

		return array(
			'Score'  => (int) $result['Score'],
			'isSpam' => ! empty( $result['isSpam'] ),
			'Reason' => isset( $result['Reason'] ) ? (string) $result['Reason'] : '',
		);
	}

	// Fallback for older OOPSpam versions: use the internal helper with the
	// 'wpregister' type, which bypasses the length-filter (login flows have
	// no real content body).
	if ( function_exists( 'oopspamantispam_call_OOPSpam' ) ) {
		$result = oopspamantispam_call_OOPSpam( '', $ip, $email, true, 'wpregister' );

		if ( ! is_array( $result ) || ! isset( $result['isItHam'] ) ) {
			return null;
		}

		return array(
			'Score'  => isset( $result['Score'] ) ? (int) $result['Score'] : 0,
			'isSpam' => false === $result['isItHam'],
			'Reason' => isset( $result['Reason'] ) ? (string) $result['Reason'] : '',
		);
	}

	return null;
}

/**
 * Return the OOPSpam-aware sender IP. Centralised so we get the same
 * proxy/CDN-aware detection as the parent plugin.
 *
 * Falls back to REMOTE_ADDR if the parent helper isn't available, or if
 * it returns empty (e.g. when OOPSpam's "don't capture IP" privacy setting
 * is on — that toggle is about what gets sent to the OOPSpam API, but our
 * LLA tracking is local-only and still needs an IP to key on).
 *
 * @return string
 */
function oopspam_ls_get_ip() {
	$ip = '';
	if ( function_exists( 'oopspamantispam_get_ip' ) ) {
		$ip = (string) oopspamantispam_get_ip();
	}
	if ( '' === $ip && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
		$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
	}
	return $ip;
}

/**
 * Activation: seed defaults, signing secret, install LLA table, schedule cron.
 */
register_activation_hook( __FILE__, 'oopspam_ls_activate' );
function oopspam_ls_activate() {
	if ( false === get_option( 'oopspam_ls_secret' ) ) {
		add_option( 'oopspam_ls_secret', wp_generate_password( 64, true, true ), '', false );
	}
	if ( false === get_option( 'oopspam_ls_settings' ) ) {
		add_option( 'oopspam_ls_settings', oopspam_ls_default_settings() );
	}

	// Limit Login Attempts table + daily cleanup cron.
	require_once OOPSPAM_LS_DIR . 'includes/class-lla.php';
	OOPSpam_LS_LLA_Store::install();

	if ( ! wp_next_scheduled( 'oopspam_ls_lla_cleanup' ) ) {
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'oopspam_ls_lla_cleanup' );
	}
}

/**
 * Deactivation: clear our cron job. Keep table + options in case the user
 * reactivates — uninstall.php is the place to fully clean up.
 */
register_deactivation_hook( __FILE__, 'oopspam_ls_deactivate' );
function oopspam_ls_deactivate() {
	wp_clear_scheduled_hook( 'oopspam_ls_lla_cleanup' );
}

/**
 * Cron handler — runs daily, purges old log rows.
 */
add_action( 'oopspam_ls_lla_cleanup', 'oopspam_ls_run_cleanup' );
function oopspam_ls_run_cleanup() {
	if ( class_exists( 'OOPSpam_LS_LLA_Store' ) ) {
		OOPSpam_LS_LLA_Store::purge_old( 30 );
	}
}

/**
 * Load includes & boot.
 */
require_once OOPSPAM_LS_DIR . 'includes/class-token.php';
require_once OOPSPAM_LS_DIR . 'includes/class-ajax.php';
require_once OOPSPAM_LS_DIR . 'includes/class-login-protector.php';
require_once OOPSPAM_LS_DIR . 'includes/class-lla.php';
require_once OOPSPAM_LS_DIR . 'includes/class-settings.php';

/**
 * Schema migration: if the stored DB version doesn't match the current one
 * (plugin was updated without re-activating), run dbDelta. Cheap autoloaded
 * option lookup; only does real work on actual upgrades.
 */
add_action( 'plugins_loaded', 'oopspam_ls_maybe_upgrade_db', 5 );
function oopspam_ls_maybe_upgrade_db() {
	if ( get_option( 'oopspam_ls_db_version' ) !== OOPSpam_LS_LLA_Store::SCHEMA_VERSION ) {
		OOPSpam_LS_LLA_Store::install();
	}
}

add_action( 'plugins_loaded', 'oopspam_ls_boot' );
function oopspam_ls_boot() {
	load_plugin_textdomain( 'oopspam-login-shield', false, dirname( OOPSPAM_LS_BASENAME ) . '/languages' );

	new OOPSpam_LS_Ajax();
	new OOPSpam_LS_Login_Protector();
	new OOPSpam_LS_LLA();

	if ( is_admin() ) {
		new OOPSpam_LS_Settings();
	}
}

/**
 * Admin notice if the OOPSpam parent plugin is missing or unconfigured.
 */
add_action( 'admin_notices', 'oopspam_ls_dependency_notice' );
function oopspam_ls_dependency_notice() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	// Database install failure — surface globally so admins see it on any
	// admin page, with a link to the Log tab where the reactivate button lives.
	$db_fail = get_option( 'oopspam_ls_db_install_failed' );
	if ( is_array( $db_fail ) ) {
		$log_url = admin_url( 'options-general.php?page=oopspam-login-shield&tab=log' );
		echo '<div class="notice notice-error"><p>';
		echo '<strong>' . esc_html__( 'OOPSpam Login Shield:', 'oopspam-login-shield' ) . '</strong> ';
		echo esc_html__( 'Could not create the login-log database table. Limit-login-attempts logging is not working until this is fixed.', 'oopspam-login-shield' );
		echo ' <a href="' . esc_url( $log_url ) . '">' . esc_html__( 'Open diagnostics &rarr;', 'oopspam-login-shield' ) . '</a>';
		echo '</p></div>';
	}

	$has_helpers = ( function_exists( 'oopspam_check_spam' ) || function_exists( 'oopspamantispam_call_OOPSpam' ) )
		&& function_exists( 'oopspamantispam_get_key' );

	if ( ! $has_helpers ) {
		echo '<div class="notice notice-warning"><p><strong>OOPSpam Login Shield:</strong> ';
		echo wp_kses_post( __( 'requires the <a href="https://wordpress.org/plugins/oopspam-anti-spam/" target="_blank" rel="noopener">OOPSpam Anti-Spam</a> plugin to be installed and active. The widget will display but will not validate requests until OOPSpam is set up.', 'oopspam-login-shield' ) );
		echo '</p></div>';
		return;
	}

	if ( empty( oopspamantispam_get_key() ) ) {
		echo '<div class="notice notice-warning"><p><strong>OOPSpam Login Shield:</strong> ';
		echo esc_html__( 'OOPSpam is active but no API key is configured. Set your key on the OOPSpam settings page so login requests can be checked.', 'oopspam-login-shield' );
		echo '</p></div>';
	}
}

/**
 * When the "take over login protection" setting is on, force OOPSpam's
 * own wp_login_activated option to 0 at read time. This prevents their
 * wp_authenticate_user filter from running its own OOPSpam check on
 * login, leaving our plugin's layer in sole charge.
 *
 * Implemented as an option-read filter (not a write to wp_options) so
 * the user's original OOPSpam settings are never actually mutated. If
 * the takeover toggle is later disabled, OOPSpam's stored config
 * returns to effect immediately, exactly as it was.
 *
 * Hooked at priority 1 so we run before anyone else who might also
 * be filtering this option.
 */
add_filter( 'option_oopspamantispam_settings', 'oopspam_ls_filter_oopspam_settings', 1 );
function oopspam_ls_filter_oopspam_settings( $value ) {
	$ours = get_option( 'oopspam_ls_settings', array() );
	if ( empty( $ours['takeover_login'] ) ) {
		return $value;
	}

	if ( ! is_array( $value ) ) {
		return $value;
	}

	// Force OOPSpam's "WP login form" toggle off without touching the
	// stored value. Their integration short-circuits when this is empty.
	$value['oopspam_is_wplogin_activated'] = 0;
	return $value;
}

/**
 * Settings link on the Plugins screen.
 */
add_filter( 'plugin_action_links_' . OOPSPAM_LS_BASENAME, 'oopspam_ls_action_links' );
function oopspam_ls_action_links( $links ) {
	$url = admin_url( 'options-general.php?page=oopspam-login-shield' );
	array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'oopspam-login-shield' ) . '</a>' );
	return $links;
}
