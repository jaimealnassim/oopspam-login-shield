<?php
/**
 * Limit Login Attempts module — simplified.
 *
 * Two tables, conceptually:
 *   - log:       every login attempt, success or failure (one row each)
 *   - lockouts:  IPs currently locked out with an expiry
 *
 * For schema simplicity we use a single table with a `success` flag (0/1)
 * for the log, and a tiny `oopspam_ls_lockouts` option for the active
 * lockout state. Options are durable (no risk of object-cache eviction
 * dropping a lockout mid-window).
 *
 * Failed attempts are recorded via TWO hooks for redundancy:
 *   - wp_login_failed (the obvious one)
 *   - wp_authenticate_user at very high priority (catches plugins that
 *     intercept the auth flow and skip wp_login_failed — Wordfence MFA,
 *     some SSO bridges, etc.)
 * A per-request flag prevents double-logging.
 *
 * @package OOPSpam_Login_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOPSpam_LS_LLA_Store {

	/** Bumped when schema changes. */
	public const SCHEMA_VERSION = '2';

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'oopspam_ls_log';
	}

	/**
	 * Create / migrate the log table. Verifies the table actually exists
	 * after dbDelta runs; falls back to direct CREATE TABLE if dbDelta
	 * silently failed; flags the failure mode for an admin notice if
	 * neither path works.
	 */
	public static function install(): void {
		global $wpdb;

		$table           = self::table();
		$charset_collate = $wpdb->get_charset_collate();

		// Schema v2: simplified to {id, ip, username, success, created_at}.
		// dbDelta is finicky about whitespace; spaces (not tabs) inside.
		$sql = "CREATE TABLE {$table} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  ip varchar(45) NOT NULL DEFAULT '',
  username varchar(60) NOT NULL DEFAULT '',
  success tinyint(1) NOT NULL DEFAULT 0,
  created_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY ip_time (ip, created_at),
  KEY created_at (created_at)
) {$charset_collate};";

		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}
		dbDelta( $sql );

		if ( self::table_exists() ) {
			delete_option( 'oopspam_ls_db_install_failed' );
			update_option( 'oopspam_ls_db_version', self::SCHEMA_VERSION, false );
			return;
		}

		// dbDelta failed → try direct CREATE.
		$wpdb->hide_errors();
		$wpdb->query( $sql );

		if ( self::table_exists() ) {
			delete_option( 'oopspam_ls_db_install_failed' );
			update_option( 'oopspam_ls_db_version', self::SCHEMA_VERSION, false );
			return;
		}

		update_option(
			'oopspam_ls_db_install_failed',
			array(
				'time'  => time(),
				'error' => $wpdb->last_error ?: 'dbDelta and direct CREATE TABLE both failed without an error message',
			),
			false
		);

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'OOPSpam Login Shield: failed to create log table. Last error: ' . $wpdb->last_error );
		}
	}

	public static function table_exists(): bool {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		return $found === $table;
	}

	/**
	 * Append a single row to the log. Self-heals if the table is missing
	 * (calls install() once, retries). Logs to error_log when WP_DEBUG is on.
	 *
	 * @param string $ip
	 * @param string $username
	 * @param bool   $success
	 * @return int|false Inserted row id, or false on failure.
	 */
	public static function log( string $ip, string $username, bool $success ): int|false {
		global $wpdb;

		$data = array(
			'ip'         => substr( $ip, 0, 45 ),
			'username'   => substr( $username, 0, 60 ),
			'success'    => $success ? 1 : 0,
			'created_at' => current_time( 'mysql', true ),
		);
		$formats = array( '%s', '%s', '%d', '%s' );

		$prev_suppress = $wpdb->suppress_errors;
		$wpdb->suppress_errors( true );
		$wpdb->hide_errors();

		$ok = $wpdb->insert( self::table(), $data, $formats );

		// Self-heal: missing-table error → run install, retry once.
		if ( ! $ok && '' !== (string) $wpdb->last_error
			&& false !== stripos( (string) $wpdb->last_error, "doesn't exist" ) ) {

			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( 'OOPSpam Login Shield: log table missing — auto-repairing.' );
			}
			self::install();
			if ( self::table_exists() ) {
				$ok = $wpdb->insert( self::table(), $data, $formats );
			}
		}

		$wpdb->suppress_errors( $prev_suppress );

		if ( ! $ok && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log(
				'OOPSpam Login Shield: log insert failed. IP=' . $ip
				. ' Username=' . $username
				. ' Success=' . ( $success ? '1' : '0' )
				. ' Error=' . ( $wpdb->last_error ?: '(empty)' )
			);
		}

		return $ok ? (int) $wpdb->insert_id : false;
	}

	/**
	 * Count failed attempts for an IP within the last $seconds.
	 */
	public static function count_failed( string $ip, int $seconds ): int {
		global $wpdb;
		if ( '' === $ip ) {
			return 0;
		}
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 1, $seconds ) );
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . self::table()
				. ' WHERE ip = %s AND success = 0 AND created_at > %s',
				$ip,
				$cutoff
			)
		);
	}

	/**
	 * Get the lockouts state map: ip => unix-timestamp-when-it-expires.
	 *
	 * @return array<string, int>
	 */
	public static function get_lockouts(): array {
		$lockouts = get_option( 'oopspam_ls_lockouts', array() );
		if ( ! is_array( $lockouts ) ) {
			return array();
		}
		// Drop already-expired entries lazily on read.
		$now      = time();
		$cleaned  = array();
		$changed  = false;
		foreach ( $lockouts as $ip => $expires ) {
			if ( (int) $expires > $now ) {
				$cleaned[ $ip ] = (int) $expires;
			} else {
				$changed = true;
			}
		}
		if ( $changed ) {
			update_option( 'oopspam_ls_lockouts', $cleaned, false );
		}
		return $cleaned;
	}

	/**
	 * Add or extend a lockout for an IP.
	 */
	public static function set_lockout( string $ip, int $expires_at ): void {
		if ( '' === $ip ) {
			return;
		}
		$lockouts = self::get_lockouts();
		// Take the longer of the existing and new expiry.
		$lockouts[ $ip ] = max( $lockouts[ $ip ] ?? 0, $expires_at );
		update_option( 'oopspam_ls_lockouts', $lockouts, false );
	}

	/**
	 * Get expiry (unix ts) for an IP, or 0 if not locked.
	 */
	public static function get_lockout_expiry( string $ip ): int {
		if ( '' === $ip ) {
			return 0;
		}
		$lockouts = self::get_lockouts();
		return (int) ( $lockouts[ $ip ] ?? 0 );
	}

	/**
	 * Clear the lockout for an IP.
	 */
	public static function clear_lockout( string $ip ): void {
		if ( '' === $ip ) {
			return;
		}
		$lockouts = self::get_lockouts();
		if ( isset( $lockouts[ $ip ] ) ) {
			unset( $lockouts[ $ip ] );
			update_option( 'oopspam_ls_lockouts', $lockouts, false );
		}
	}

	/* --------------------------------------------------------------------
	 * Admin queries
	 * ------------------------------------------------------------------ */

	/**
	 * Get total log entries.
	 */
	public static function get_total(): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::table() );
	}

	/**
	 * Get a page of log entries, newest first.
	 *
	 * @return array<int, object>
	 */
	public static function get_entries( int $per_page = 25, int $offset = 0 ): array {
		global $wpdb;
		return (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM ' . self::table() . '
				 ORDER BY id DESC
				 LIMIT %d OFFSET %d',
				max( 1, $per_page ),
				max( 0, $offset )
			)
		);
	}

	/**
	 * Delete log rows older than $days.
	 */
	public static function purge_old( int $days = 30 ): int {
		global $wpdb;
		$days   = max( 1, (int) apply_filters( 'oopspam_ls_lla_log_retention_days', $days ) );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );

		return (int) $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM ' . self::table() . ' WHERE created_at < %s',
				$cutoff
			)
		);
	}

	public static function clear_all(): bool {
		global $wpdb;
		return false !== $wpdb->query( 'DELETE FROM ' . self::table() );
	}

	public static function drop_table(): void {
		global $wpdb;
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::table() );
		delete_option( 'oopspam_ls_db_version' );
		delete_option( 'oopspam_ls_lockouts' );
		delete_option( 'oopspam_ls_db_install_failed' );
	}

	/**
	 * Parse the admin-configured honeypot list into an array of clean entries.
	 *
	 * Accepts a textarea blob with one entry per line (or comma-separated).
	 * Returns lowercased entries, with blank lines and "#" comment lines stripped.
	 *
	 * @param string $raw
	 * @return array<int, string>
	 */
	public static function parse_honeypot_list( string $raw ): array {
		// Normalize: split on newlines AND commas, so admins can paste either way.
		$parts = preg_split( '/[\r\n,]+/', $raw );
		if ( ! $parts ) {
			return array();
		}
		$out = array();
		foreach ( $parts as $entry ) {
			$entry = strtolower( trim( $entry ) );
			if ( '' === $entry || str_starts_with( $entry, '#' ) ) {
				continue;
			}
			$out[] = $entry;
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Test whether a submitted login matches any entry in the honeypot list.
	 *
	 * Matching is case-insensitive. Three rules apply:
	 *
	 *   - Plain string (e.g. "admin"): exact match against the submitted login.
	 *   - "local@*" pattern (e.g. "admin@*"): matches any email whose local
	 *     part matches "local". Catches the "admin@<your-site-domain>" trick
	 *     bots use when they don't know the actual admin email.
	 *   - "local@domain" pattern: exact email match.
	 *
	 * The submitted login can be either a username or an email. If it
	 * contains "@", we treat it as an email and check both the full email
	 * and the local-part wildcard rules.
	 *
	 * @param string $submitted Username or email submitted to the login form.
	 * @param array<int, string> $honeypot Already-parsed honeypot list.
	 * @return bool
	 */
	public static function login_matches_honeypot( string $submitted, array $honeypot ): bool {
		$submitted = strtolower( trim( $submitted ) );
		if ( '' === $submitted || empty( $honeypot ) ) {
			return false;
		}

		$is_email     = false !== strpos( $submitted, '@' );
		$submitted_lp = $is_email ? substr( $submitted, 0, strpos( $submitted, '@' ) ) : '';

		foreach ( $honeypot as $entry ) {
			// Wildcard pattern: "local@*"
			if ( str_ends_with( $entry, '@*' ) ) {
				$pattern_lp = substr( $entry, 0, -2 );

				// Wildcard matches both:
				//   1. an email submission whose local-part equals the pattern
				//      (admin@anywhere.com matches "admin@*")
				//   2. a bare-username submission equal to the pattern
				//      ("admin" alone, no @, also matches "admin@*")
				// The second case catches the "I only allow emails but a bot
				// just typed 'admin'" scenario you described.
				if ( $is_email && $submitted_lp === $pattern_lp ) {
					return true;
				}
				if ( ! $is_email && $submitted === $pattern_lp ) {
					return true;
				}
				continue;
			}

			// Exact match (works for both bare usernames and full emails).
			if ( $submitted === $entry ) {
				return true;
			}
		}

		return false;
	}
}


/**
 * Auth-flow integration: log every attempt, gate at threshold.
 *
 * Hook ordering on `authenticate`:
 *   priority 1   — gate(): if locked out, return WP_Error before WP checks the password
 *   priority 20  — wp_authenticate_username_password (core)
 *   priority 30  — OOPSpam_LS_Login_Protector::authenticate (token + final OOPSpam call)
 *
 * Failure recording uses two hooks (wp_login_failed + wp_authenticate_user)
 * so we catch attempts even when other auth-flow plugins skip the canonical
 * wp_login_failed action.
 */
class OOPSpam_LS_LLA {

	/**
	 * Per-request guard so primary + backup hooks don't both record the same attempt.
	 */
	private static bool $request_recorded = false;

	public function __construct() {
		$settings = oopspam_ls_get_settings();
		if ( empty( $settings['lla_enabled'] ) ) {
			return;
		}

		add_filter( 'authenticate',         $this->gate( ... ),                 1, 3 );
		add_action( 'wp_login_failed',      $this->on_failed( ... ),           10, 2 );
		add_filter( 'wp_authenticate_user', $this->on_authenticate_user( ... ), 99999, 2 );
		add_action( 'wp_login',             $this->on_success( ... ),          10, 2 );
		add_action( 'login_init',           $this->maybe_block_login_page( ... ), 1 );
	}

	/**
	 * If the IP is currently locked out, replace wp-login.php with a styled
	 * lockout notice (no form rendered).
	 */
	public function maybe_block_login_page(): void {
		if ( is_user_logged_in() ) {
			return;
		}

		$action = isset( $_REQUEST['action'] )
			? sanitize_key( wp_unslash( (string) $_REQUEST['action'] ) )
			: 'login';

		if ( ! in_array( $action, array( 'login', 'register', 'lostpassword', 'retrievepassword' ), true ) ) {
			return;
		}

		if ( apply_filters( 'oopspam_ls_lla_bypass', false ) ) {
			return;
		}

		$ip = oopspam_ls_get_ip();
		if ( '' === $ip ) {
			return;
		}

		$expires = OOPSpam_LS_LLA_Store::get_lockout_expiry( $ip );
		if ( $expires <= time() ) {
			return;
		}

		$this->render_locked_page( $expires );
	}

	private function render_locked_page( int $expires_ts ): void {
		$mins_left = max( 1, (int) ceil( ( $expires_ts - time() ) / 60 ) );
		$human     = $mins_left >= 60
			? human_time_diff( time(), $expires_ts )
			: sprintf( _n( '%d minute', '%d minutes', $mins_left, 'oopspam-login-shield' ), $mins_left );

		$message = sprintf(
			/* translators: %s: time remaining */
			__( 'Too many failed login attempts. Please try again in %s.', 'oopspam-login-shield' ),
			$human
		);

		nocache_headers();
		status_header( 429 );
		login_header(
			esc_html__( 'Login locked', 'oopspam-login-shield' ),
			'<p class="message">' . esc_html( $message ) . '</p>'
		);
		?>
		<p style="text-align:center; margin-top:24px;">
			<a href="<?php echo esc_url( home_url( '/' ) ); ?>">
				&larr; <?php echo esc_html( get_bloginfo( 'name' ) ); ?>
			</a>
		</p>
		<?php
		login_footer();
		exit;
	}

	/**
	 * Pre-flight gate on the authenticate filter — block locked IPs before
	 * any password check runs.
	 */
	public function gate( mixed $user, string $username, string $password ): mixed {
		if ( is_wp_error( $user ) ) {
			return $user;
		}
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return $user;
		}
		if ( '' === $username ) {
			return $user;
		}

		$ip = oopspam_ls_get_ip();
		if ( '' === $ip ) {
			return $user;
		}

		$expires = OOPSpam_LS_LLA_Store::get_lockout_expiry( $ip );
		if ( $expires <= time() ) {
			return $user;
		}

		$mins_left = max( 1, (int) ceil( ( $expires - time() ) / 60 ) );
		$msg = sprintf(
			/* translators: %d: minutes */
			_n( 'Too many failed attempts. Please try again in %d minute.', 'Too many failed attempts. Please try again in %d minutes.', $mins_left, 'oopspam-login-shield' ),
			$mins_left
		);

		return new WP_Error(
			'oopspam_ls_locked',
			'<strong>' . esc_html__( 'Locked:', 'oopspam-login-shield' ) . '</strong> ' . esc_html( $msg )
		);
	}

	/**
	 * Primary failure recorder — wp_login_failed.
	 */
	public function on_failed( string $username, mixed $error = null ): void {
		if ( self::$request_recorded ) {
			return;
		}
		$this->record( $username, false );
	}

	/**
	 * Backup failure recorder — wp_authenticate_user filter at p99999.
	 * Catches "user found, password wrong" failures even when wp_login_failed
	 * is skipped by a different auth-flow plugin. Always returns $user
	 * unchanged (we use it as a read-only observer).
	 */
	public function on_authenticate_user( mixed $user, string $password = '' ): mixed {
		if ( self::$request_recorded ) {
			return $user;
		}
		if ( ! is_wp_error( $user ) ) {
			return $user;
		}

		$username = '';
		if ( ! empty( $_REQUEST['log'] ) ) {
			$username = sanitize_text_field( wp_unslash( (string) $_REQUEST['log'] ) );
		}

		$this->record( $username, false );
		return $user;
	}

	/**
	 * Success recorder — wp_login.
	 */
	public function on_success( string $user_login, mixed $user = null ): void {
		if ( self::$request_recorded ) {
			return;
		}
		$this->record( $user_login, true );
	}

	/**
	 * Shared recording path used by all three hooks.
	 *
	 * For failed attempts: also checks lockout thresholds and triggers a
	 * lockout when hit. Already-locked IPs do NOT increment the counter
	 * (otherwise the count bleeds forward past lockout expiry).
	 */
	private function record( string $username, bool $success ): void {
		$ip = oopspam_ls_get_ip();
		if ( '' === $ip ) {
			return;
		}

		self::$request_recorded = true;

		// Always log, successes too, so admins can audit.
		OOPSpam_LS_LLA_Store::log( $ip, $username, $success );

		if ( $success ) {
			return;
		}

		// Already locked, don't count this attempt against the threshold.
		if ( OOPSpam_LS_LLA_Store::get_lockout_expiry( $ip ) > time() ) {
			return;
		}

		$settings = oopspam_ls_get_settings();

		// Honeypot trip: if the submitted username/email matches a configured
		// honeypot entry, skip threshold counting and lock the IP straight
		// out. No real user types "admin" or "admin@<your-domain>" by accident
		// when you've configured the site differently. This is the lever for
		// admins who only allow email login but bots keep trying usernames.
		if ( ! empty( $settings['lla_honeypot_enabled'] ) ) {
			$honeypot = OOPSpam_LS_LLA_Store::parse_honeypot_list(
				(string) ( $settings['lla_honeypot_logins'] ?? '' )
			);
			if ( OOPSpam_LS_LLA_Store::login_matches_honeypot( $username, $honeypot ) ) {
				$hours   = max( 1, (int) $settings['lla_honeypot_hours'] );
				$expires = time() + $hours * HOUR_IN_SECONDS;
				OOPSpam_LS_LLA_Store::set_lockout( $ip, $expires );

				/**
				 * Fires when an IP is auto-locked because the submitted login
				 * matched a honeypot entry.
				 *
				 * @param string $ip       Sender IP.
				 * @param string $username Submitted username/email that tripped the honeypot.
				 * @param int    $expires  Unix timestamp when the lockout expires.
				 */
				do_action( 'oopspam_ls_lla_honeypot_trip', $ip, $username, $expires );

				return;
			}
		}

		$max_attempts  = max( 2, (int) $settings['lla_max_attempts'] );
		$short_minutes = max( 1, (int) $settings['lla_lockout_minutes'] );
		$max_lockouts  = max( 1, (int) $settings['lla_max_lockouts'] );
		$long_hours    = max( 1, (int) $settings['lla_long_hours'] );

		// How many fails inside the rolling window?
		$failed = OOPSpam_LS_LLA_Store::count_failed( $ip, $short_minutes * MINUTE_IN_SECONDS );
		if ( $failed < $max_attempts ) {
			return;
		}

		// Trigger short lockout. If they've already had $max_lockouts in the
		// last 24h, escalate to the long lockout instead.
		$failed_24h = OOPSpam_LS_LLA_Store::count_failed( $ip, 24 * HOUR_IN_SECONDS );
		// Each "lockout" represents one batch of $max_attempts fails.
		$lockout_batches = (int) floor( $failed_24h / $max_attempts );

		$expires = $lockout_batches >= $max_lockouts
			? time() + $long_hours * HOUR_IN_SECONDS
			: time() + $short_minutes * MINUTE_IN_SECONDS;

		OOPSpam_LS_LLA_Store::set_lockout( $ip, $expires );

		do_action( 'oopspam_ls_lla_lockout', $ip, $username, $expires, $failed );
	}
}
