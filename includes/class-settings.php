<?php
/**
 * Admin page (Settings → Login Shield).
 *
 * Two tabs:
 *   - settings: form for verification + LLA configuration
 *   - log:      audit view of login events + active lockouts (with manual unlock)
 *
 * @package OOPSpam_Login_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOPSpam_LS_Settings {

	const OPTION_GROUP = 'oopspam_ls_settings_group';
	const OPTION_NAME  = 'oopspam_ls_settings';
	const PAGE_SLUG    = 'oopspam-login-shield';

	const NONCE_UNLOCK    = 'oopspam_ls_unlock';
	const NONCE_CLEAR_LOG = 'oopspam_ls_clear_log';

	public function __construct() {
		add_action( 'admin_menu', $this->menu( ... ) );
		add_action( 'admin_init', $this->register( ... ) );

		// admin-post.php handlers for log-tab actions.
		add_action( 'admin_post_oopspam_ls_unlock',         $this->handle_unlock( ... ) );
		add_action( 'admin_post_oopspam_ls_clear_log',      $this->handle_clear_log( ... ) );
		add_action( 'admin_post_oopspam_ls_reactivate_lla', $this->handle_reactivate( ... ) );

		// Enqueue admin table assets only on the Log tab.
		add_action( 'admin_enqueue_scripts', $this->maybe_enqueue_admin_assets( ... ) );
	}

	/**
	 * Conditionally enqueue the table CSS/JS — only on our settings page,
	 * Log tab. Keeps these assets off every other admin screen.
	 */
	public function maybe_enqueue_admin_assets( string $hook ): void {
		// $hook for an add_options_page is "settings_page_<slug>".
		if ( 'settings_page_' . self::PAGE_SLUG !== $hook ) {
			return;
		}
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( (string) $_GET['tab'] ) ) : 'settings';

		// admin.css is shared between the Settings and Log tabs (the Settings
		// tab uses it for the country picker; the Log tab uses it for the
		// attempts table and lockout badges).
		if ( 'settings' !== $tab && 'log' !== $tab ) {
			return;
		}

		wp_enqueue_style(
			'oopspam-ls-admin',
			OOPSPAM_LS_URL . 'assets/admin.css',
			array(),
			OOPSPAM_LS_VERSION
		);

		// Country picker enhancement only on the Settings tab.
		if ( 'settings' === $tab ) {
			wp_enqueue_script(
				'oopspam-ls-country-picker',
				OOPSPAM_LS_URL . 'assets/admin-country-picker.js',
				array(),
				OOPSPAM_LS_VERSION,
				true
			);

			// Critical picker styles, inlined into the page response. Belt-and-
			// suspenders against the external admin.css being stale-cached on
			// mobile browsers (Brave Android in particular). Cache busting via
			// version query string isn't always honored, but inline styles
			// arrive in the HTML itself and can't be cached separately.
			wp_add_inline_style( 'oopspam-ls-admin', self::picker_inline_css() );
		}
	}

	/**
	 * The minimum CSS the country picker needs to be usable.
	 * Duplicates a subset of admin.css so the picker still renders correctly
	 * even when the external CSS file fails to load fresh.
	 */
	private static function picker_inline_css(): string {
		return '
.oopspam-ls-country-picker { max-width: 760px; margin: 0 0 14px 0; padding: 14px; border: 1px solid #c3c4c7; border-radius: 4px; background: #fff; }
.oopspam-ls-region-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.oopspam-ls-region-btn.is-active { background: #e6f0fa !important; border-color: #2271b1 !important; color: #135e96 !important; }
.oopspam-ls-region-btn.is-remove { color: #b32d2e !important; border-color: #d4a3a4 !important; }
.oopspam-ls-picker-status { font-size: 12px; color: #50575e; margin-bottom: 10px; padding: 6px 10px; background: #f6f7f7; border-radius: 3px; display: inline-block; }
.oopspam-ls-country-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 4px; max-height: 320px; overflow-y: auto; padding: 8px; border: 1px solid #dcdcde; border-radius: 3px; background: #fafbfc; }
.oopspam-ls-chip { display: block; width: 100%; padding: 6px 10px; background: #fff; border: 1px solid #dcdcde; border-radius: 3px; font-size: 12px; cursor: pointer; color: #1d2327; text-align: left; line-height: 1.4; min-height: 32px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.oopspam-ls-chip:hover { background: #f0f0f1; border-color: #8c8f94; }
.oopspam-ls-chip.is-selected { background: #2271b1; border-color: #135e96; color: #fff; }
.oopspam-ls-chip-code { display: inline-block; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 700; font-size: 11px; padding: 1px 5px; margin-right: 7px; background: #f0f0f1; color: #1d2327; border-radius: 2px; vertical-align: middle; }
.oopspam-ls-chip.is-selected .oopspam-ls-chip-code { background: rgba(255,255,255,0.22); color: #fff; }
.oopspam-ls-chip-name { display: inline; color: inherit; font-size: 12px; vertical-align: middle; }
.oopspam-ls-picker-hidden { display: none !important; }
@media (max-width: 600px) {
	.oopspam-ls-country-grid { grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); max-height: 280px; }
	.oopspam-ls-chip { padding: 8px 10px; min-height: 36px; }
}
';
	}

	public function menu() {
		add_options_page(
			__( 'OOPSpam Login Shield', 'oopspam-login-shield' ),
			__( 'Login Shield', 'oopspam-login-shield' ),
			'manage_options',
			self::PAGE_SLUG,
			array( $this, 'render' )
		);
	}

	public function register() {
		register_setting(
			self::OPTION_GROUP,
			self::OPTION_NAME,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize' ),
				'default'           => oopspam_ls_default_settings(),
			)
		);
	}

	/**
	 * Sanitize all settings, including the new LLA fields.
	 *
	 * Numeric fields are clamped to safe ranges so that an extremely low or
	 * high value (e.g. 0 attempts, 9999 hour lockout) can't break the auth flow.
	 */
	public function sanitize( $input ) {
		$defaults = oopspam_ls_default_settings();
		$clean    = array();

		$clean['enabled']              = ! empty( $input['enabled'] )              ? 1 : 0;
		$clean['protect_login']        = ! empty( $input['protect_login'] )        ? 1 : 0;
		$clean['protect_register']     = ! empty( $input['protect_register'] )     ? 1 : 0;
		$clean['protect_lostpassword'] = ! empty( $input['protect_lostpassword'] ) ? 1 : 0;

		// Radio button — explicitly compare to "1" so "0" is correctly stored as 0.
		$clean['auto_verify'] = ( isset( $input['auto_verify'] ) && '1' === (string) $input['auto_verify'] ) ? 1 : 0;

		$clean['spam_message'] = isset( $input['spam_message'] ) && '' !== trim( (string) $input['spam_message'] )
			? sanitize_text_field( $input['spam_message'] )
			: $defaults['spam_message'];

		$clean['fail_message'] = isset( $input['fail_message'] ) && '' !== trim( (string) $input['fail_message'] )
			? sanitize_text_field( $input['fail_message'] )
			: $defaults['fail_message'];

		// Coordination with OOPSpam Anti-Spam.
		$clean['takeover_login'] = ! empty( $input['takeover_login'] ) ? 1 : 0;

		// Connector-specific rules (mode-based).
		$clean['connector_block_vpn_mode']        = self::clamp_mode( $input['connector_block_vpn_mode']        ?? null, array( 'inherit', 'block' ),  'inherit' );
		$clean['connector_block_datacenter_mode'] = self::clamp_mode( $input['connector_block_datacenter_mode'] ?? null, array( 'inherit', 'block' ),  'inherit' );
		$clean['connector_block_temp_email_mode'] = self::clamp_mode( $input['connector_block_temp_email_mode'] ?? null, array( 'inherit', 'block' ),  'inherit' );
		$clean['connector_country_mode']          = self::clamp_mode( $input['connector_country_mode']          ?? null, array( 'inherit', 'custom' ), 'inherit' );

		// Country list: ISO 2-letter codes, comma- or newline-separated.
		// Stored regardless of mode so toggling mode preserves the list.
		$raw_countries = isset( $input['connector_blocked_countries'] )
			? (string) $input['connector_blocked_countries']
			: '';
		$parts = preg_split( '/[\s,]+/', $raw_countries );
		$valid = array();
		foreach ( (array) $parts as $code ) {
			$code = strtoupper( trim( (string) $code ) );
			if ( 2 === strlen( $code ) && ctype_alpha( $code ) ) {
				$valid[] = $code;
			}
		}
		$clean['connector_blocked_countries'] = implode( ', ', array_values( array_unique( $valid ) ) );

		// Require JavaScript at login.
		$clean['require_js'] = ! empty( $input['require_js'] ) ? 1 : 0;

		// Limit Login Attempts.
		$clean['lla_enabled'] = ! empty( $input['lla_enabled'] ) ? 1 : 0;

		$clean['lla_max_attempts']    = self::clamp_int( $input['lla_max_attempts']    ?? null, 2,   50,    $defaults['lla_max_attempts']    );
		$clean['lla_lockout_minutes'] = self::clamp_int( $input['lla_lockout_minutes'] ?? null, 1,   720,   $defaults['lla_lockout_minutes'] );
		$clean['lla_max_lockouts']    = self::clamp_int( $input['lla_max_lockouts']    ?? null, 1,   20,    $defaults['lla_max_lockouts']    );
		$clean['lla_long_hours']      = self::clamp_int( $input['lla_long_hours']      ?? null, 1,   168,   $defaults['lla_long_hours']      );

		// Honeypot logins.
		$clean['lla_honeypot_enabled'] = ! empty( $input['lla_honeypot_enabled'] ) ? 1 : 0;
		$clean['lla_honeypot_hours']   = self::clamp_int( $input['lla_honeypot_hours'] ?? null, 1, 720, $defaults['lla_honeypot_hours'] );

		// Honeypot list: textarea blob. Only sanitize_textarea_field, then run it
		// through the parser to dedupe and lowercase, then rejoin so the saved
		// value is always normalized.
		$honeypot_raw = isset( $input['lla_honeypot_logins'] )
			? sanitize_textarea_field( (string) $input['lla_honeypot_logins'] )
			: $defaults['lla_honeypot_logins'];
		$parsed       = OOPSpam_LS_LLA_Store::parse_honeypot_list( $honeypot_raw );
		$clean['lla_honeypot_logins'] = implode( "\n", $parsed );

		return $clean;
	}

	private static function clamp_int( mixed $value, int $min, int $max, int $default ): int {
		if ( null === $value || '' === $value || ! is_numeric( $value ) ) {
			return $default;
		}
		return max( $min, min( $max, (int) $value ) );
	}

	/**
	 * Validate a string against a fixed set of allowed values.
	 * Used for radio-button-style mode settings (inherit | block | custom etc).
	 */
	private static function clamp_mode( mixed $value, array $allowed, string $default ): string {
		$v = is_string( $value ) ? trim( $value ) : '';
		return in_array( $v, $allowed, true ) ? $v : $default;
	}

	/* -----------------------------------------------------------------------
	 * Page rendering
	 * --------------------------------------------------------------------- */

	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'settings';
		if ( ! in_array( $tab, array( 'settings', 'log', 'about' ), true ) ) {
			$tab = 'settings';
		}

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'OOPSpam Login Shield', 'oopspam-login-shield' ); ?></h1>

			<h2 class="nav-tab-wrapper" style="margin-bottom:16px;">
				<a href="<?php echo esc_url( $this->tab_url( 'settings' ) ); ?>" class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Settings', 'oopspam-login-shield' ); ?>
				</a>
				<a href="<?php echo esc_url( $this->tab_url( 'log' ) ); ?>" class="nav-tab <?php echo 'log' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Login Log', 'oopspam-login-shield' ); ?>
				</a>
				<a href="<?php echo esc_url( $this->tab_url( 'about' ) ); ?>" class="nav-tab <?php echo 'about' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'About', 'oopspam-login-shield' ); ?>
				</a>
			</h2>

			<?php
			match ( $tab ) {
				'log'   => $this->render_log_tab(),
				'about' => $this->render_about_tab(),
				default => $this->render_settings_tab(),
			};
			?>
		</div>
		<?php
	}

	private function tab_url( string $tab ): string {
		return add_query_arg(
			array(
				'page' => self::PAGE_SLUG,
				'tab'  => $tab,
			),
			admin_url( 'options-general.php' )
		);
	}

	/* -----------------------------------------------------------------------
	 * Settings tab
	 * --------------------------------------------------------------------- */

	private function render_settings_tab(): void {
		$s         = oopspam_ls_get_settings();
		$has_oop   = ( function_exists( 'oopspam_check_spam' ) || function_exists( 'oopspamantispam_call_OOPSpam' ) )
			&& function_exists( 'oopspamantispam_get_key' );
		$has_key   = $has_oop && ! empty( oopspamantispam_get_key() );
		$login_url = wp_login_url();
		?>
		<p style="max-width:760px;">
			<?php esc_html_e( 'Adds a checkbox-style verification widget to the WordPress login, registration, and lost-password forms. Each request is checked against the OOPSpam API for known-bad IPs, VPN/datacenter origin, blocked keywords/emails, country rules, and rate limits, and locks out repeat offenders.', 'oopspam-login-shield' ); ?>
		</p>

		<?php if ( ! $has_oop ) : ?>
			<div class="notice notice-error inline"><p>
				<?php
				echo wp_kses_post(
					sprintf(
						/* translators: %s: link to OOPSpam plugin */
						__( 'The %s plugin is not installed or active. This plugin acts as a connector and requires the parent plugin to function.', 'oopspam-login-shield' ),
						'<a href="https://wordpress.org/plugins/oopspam-anti-spam/" target="_blank" rel="noopener">OOPSpam Anti-Spam</a>'
					)
				);
				?>
			</p></div>
		<?php elseif ( ! $has_key ) : ?>
			<div class="notice notice-warning inline"><p>
				<?php
				echo wp_kses_post(
					sprintf(
						/* translators: %s: link to OOPSpam settings */
						__( 'OOPSpam is active but no API key is set. Please add your key on the %s.', 'oopspam-login-shield' ),
						'<a href="' . esc_url( admin_url( 'options-general.php?page=oopspamantispam' ) ) . '">' . esc_html__( 'OOPSpam settings page', 'oopspam-login-shield' ) . '</a>'
					)
				);
				?>
			</p></div>
		<?php else : ?>
			<div class="notice notice-success inline"><p>
				<?php esc_html_e( 'OOPSpam is active and an API key is configured. The widget will verify against the OOPSpam API.', 'oopspam-login-shield' ); ?>
			</p></div>
		<?php endif; ?>

		<?php
		// Coordination notice: as of OOPSpam 1.2.68, the parent plugin has its
		// own login protection. When that's enabled, our final OOPSpam check
		// at submit time would duplicate theirs (double API calls, doubled
		// false-positive risk). We auto-detect and skip our duplicate; this
		// notice tells the admin what's happening so they can confirm.
		if ( function_exists( 'oopspam_ls_oopspam_handles_login' ) && oopspam_ls_oopspam_handles_login() ) :
			?>
			<div class="notice notice-info inline"><p>
				<strong><?php esc_html_e( 'Coordinated with OOPSpam:', 'oopspam-login-shield' ); ?></strong>
				<?php
				echo wp_kses_post(
					sprintf(
						/* translators: %s: link to OOPSpam settings */
						__( 'OOPSpam Anti-Spam is currently running its own login protection (the "Spam protection on the WordPress login form" toggle is on in %s). To avoid double-checking and duplicate API quota usage, this plugin will skip its final OOPSpam call at login submit. Everything else (the verification widget, token check, limit-login-attempts, honeypot, audit log) continues to work normally.', 'oopspam-login-shield' ),
						'<a href="' . esc_url( admin_url( 'options-general.php?page=oopspamantispam' ) ) . '">' . esc_html__( 'OOPSpam settings', 'oopspam-login-shield' ) . '</a>'
					)
				);
				?>
			</p></div>
		<?php endif; ?>

		<form action="options.php" method="post">
			<?php settings_fields( self::OPTION_GROUP ); ?>

			<h2 class="title"><?php esc_html_e( 'Verification widget', 'oopspam-login-shield' ); ?></h2>

			<table class="form-table" role="presentation">

				<tr>
					<th scope="row"><?php esc_html_e( 'Enable Login Shield', 'oopspam-login-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="oopspam_ls_settings[enabled]" value="1" <?php checked( $s['enabled'], 1 ); ?>>
							<?php esc_html_e( 'Master on/off switch for the verification widget.', 'oopspam-login-shield' ); ?>
						</label>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Protect forms', 'oopspam-login-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="oopspam_ls_settings[protect_login]" value="1" <?php checked( $s['protect_login'], 1 ); ?>>
							<?php esc_html_e( 'Login form', 'oopspam-login-shield' ); ?>
						</label><br>
						<label>
							<input type="checkbox" name="oopspam_ls_settings[protect_register]" value="1" <?php checked( $s['protect_register'], 1 ); ?>>
							<?php esc_html_e( 'Registration form', 'oopspam-login-shield' ); ?>
						</label><br>
						<label>
							<input type="checkbox" name="oopspam_ls_settings[protect_lostpassword]" value="1" <?php checked( $s['protect_lostpassword'], 1 ); ?>>
							<?php esc_html_e( 'Lost password form', 'oopspam-login-shield' ); ?>
						</label>
						<p class="description">
							<?php esc_html_e( 'OOPSpam already protects the registration form via its own integration; enabling it here adds the visible widget plus a token check that stops bots before any API quota is used.', 'oopspam-login-shield' ); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Verification mode', 'oopspam-login-shield' ); ?></th>
					<td>
						<fieldset>
							<legend class="screen-reader-text"><?php esc_html_e( 'Verification mode', 'oopspam-login-shield' ); ?></legend>
							<label style="display:block; margin-bottom:6px;">
								<input type="radio" name="oopspam_ls_settings[auto_verify]" value="1" <?php checked( (int) $s['auto_verify'], 1 ); ?>>
								<strong><?php esc_html_e( 'Auto-verify on page load.', 'oopspam-login-shield' ); ?></strong>
								<?php esc_html_e( 'Altcha-style. The widget verifies as soon as the form loads, with no interaction needed in most cases.', 'oopspam-login-shield' ); ?>
							</label>
							<label style="display:block;">
								<input type="radio" name="oopspam_ls_settings[auto_verify]" value="0" <?php checked( (int) $s['auto_verify'], 0 ); ?>>
								<strong><?php esc_html_e( 'Require the user to click the checkbox.', 'oopspam-login-shield' ); ?></strong>
								<?php esc_html_e( 'reCAPTCHA-style. The visitor must click the checkbox before the form can be submitted.', 'oopspam-login-shield' ); ?>
							</label>
						</fieldset>
						<p class="description">
							<?php esc_html_e( 'Either way, the form cannot be submitted until verification has succeeded.', 'oopspam-login-shield' ); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row"><label for="oopspam_ls_spam_message"><?php esc_html_e( 'Spam-blocked message', 'oopspam-login-shield' ); ?></label></th>
					<td>
						<input type="text" id="oopspam_ls_spam_message" class="large-text" name="oopspam_ls_settings[spam_message]" value="<?php echo esc_attr( $s['spam_message'] ); ?>">
						<p class="description"><?php esc_html_e( 'Shown when OOPSpam classifies the request as spam (bad IP, VPN, blocked country, etc.).', 'oopspam-login-shield' ); ?></p>
					</td>
				</tr>

				<tr>
					<th scope="row"><label for="oopspam_ls_fail_message"><?php esc_html_e( 'Verification-failure message', 'oopspam-login-shield' ); ?></label></th>
					<td>
						<input type="text" id="oopspam_ls_fail_message" class="large-text" name="oopspam_ls_settings[fail_message]" value="<?php echo esc_attr( $s['fail_message'] ); ?>">
						<p class="description"><?php esc_html_e( 'Shown in the widget when the AJAX check fails (network error, expired token, etc.).', 'oopspam-login-shield' ); ?></p>
					</td>
				</tr>

			</table>

			<h2 class="title" style="margin-top:32px;"><?php esc_html_e( 'Coordinate with OOPSpam Anti-Spam', 'oopspam-login-shield' ); ?></h2>
			<p style="max-width:760px;">
				<?php esc_html_e( "As of OOPSpam Anti-Spam 1.2.68, the official plugin ships its own login-form protection. If both layers run at the same time, every login attempt fires two independent OOPSpam classifications, which doubles your API quota usage and the chance of a false-positive lockout for legitimate users on edge-case IPs (mobile networks, hotel WiFi, VPNs).", 'oopspam-login-shield' ); ?>
			</p>
			<p style="max-width:760px;">
				<?php esc_html_e( 'Use the toggle below to make this plugin the sole authority on login protection. It will keep their toggle in the off position regardless of what is saved on their settings page.', 'oopspam-login-shield' ); ?>
			</p>

			<table class="form-table" role="presentation">

				<tr>
					<th scope="row"><?php esc_html_e( 'Take over login protection', 'oopspam-login-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="oopspam_ls_settings[takeover_login]" value="1" <?php checked( ! empty( $s['takeover_login'] ), true ); ?>>
							<?php esc_html_e( "Force OOPSpam's built-in login protection off, so this plugin is the only layer running on the login form.", 'oopspam-login-shield' ); ?>
						</label>
						<p class="description">
							<?php esc_html_e( "This does not modify OOPSpam's stored settings. We override their toggle at read-time only. If you uncheck this later, their original setting takes effect again immediately.", 'oopspam-login-shield' ); ?>
						</p>
						<?php
						// Show current effective state so admins can see whether
						// their toggle is actually being suppressed right now.
						if ( function_exists( 'oopspam_ls_oopspam_handles_login' ) ) {
							$opts_raw = get_option( 'oopspamantispam_settings' );
							$their_toggle_set = is_array( $opts_raw )
								&& ! empty( $opts_raw['oopspam_is_wplogin_activated'] )
								&& 1 == $opts_raw['oopspam_is_wplogin_activated'];

							$constant_locked = defined( 'OOPSPAM_IS_WPLOGIN_ACTIVATED' );

							if ( $constant_locked ) {
								echo '<p class="description" style="color:#b32d2e;">';
								esc_html_e( "Note: the OOPSPAM_IS_WPLOGIN_ACTIVATED constant is defined in wp-config.php (or another mu-plugin). That constant overrides everything, so the takeover setting cannot suppress it. Remove or change the constant if you want this plugin to take over.", 'oopspam-login-shield' );
								echo '</p>';
							} elseif ( $their_toggle_set && ! empty( $s['takeover_login'] ) ) {
								echo '<p class="description" style="color:#1a7e1a;">';
								esc_html_e( "Currently active. OOPSpam's login toggle is set on their side, but suppressed by this plugin.", 'oopspam-login-shield' );
								echo '</p>';
							} elseif ( $their_toggle_set ) {
								echo '<p class="description" style="color:#b26900;">';
								esc_html_e( "OOPSpam's login toggle is currently on. Until you enable takeover above (or turn it off on their settings page), both layers will run on every login.", 'oopspam-login-shield' );
								echo '</p>';
							}
						}
						?>
					</td>
				</tr>

			</table>

			<h2 class="title" style="margin-top:32px;"><?php esc_html_e( 'Connector-specific rules', 'oopspam-login-shield' ); ?></h2>
			<p style="max-width:760px;">
				<?php esc_html_e( "Apply stricter spam rules at login than the rest of the site uses. These settings only affect login, registration, and lost-password attempts. They do not change the OOPSpam plugin's sitewide behavior.", 'oopspam-login-shield' ); ?>
			</p>
			<p style="max-width:760px;">
				<?php esc_html_e( "Each rule has two modes. 'Inherit' uses whatever the OOPSpam plugin is currently set to (so if you've turned VPN blocking on sitewide, we block at login too). 'Block at login' forces the rule on regardless, which is useful if you want admins to come from clean IPs even though you allow VPN traffic to read the rest of the site.", 'oopspam-login-shield' ); ?>
			</p>
			<p style="max-width:760px; color:#646970; font-size:13px;">
				<?php esc_html_e( 'Note: when any rule is set to override mode, this plugin calls the OOPSpam API directly with our parameters instead of going through the OOPSpam plugin wrapper. Your existing API key is reused; no separate setup is required.', 'oopspam-login-shield' ); ?>
			</p>

			<table class="form-table" role="presentation">

				<tr>
					<th scope="row"><?php esc_html_e( 'Block VPN/proxy', 'oopspam-login-shield' ); ?></th>
					<td>
						<fieldset>
							<legend class="screen-reader-text"><?php esc_html_e( 'Block VPN/proxy mode', 'oopspam-login-shield' ); ?></legend>
							<?php
							$vpn_mode = $s['connector_block_vpn_mode'] ?? 'inherit';
							$ipfilter_opts = get_option( 'oopspamantispam_ipfiltering_settings', array() );
							$inherited_vpn = is_array( $ipfilter_opts ) && ! empty( $ipfilter_opts['oopspam_block_vpns'] );
							?>
							<label style="display:block; margin-bottom:4px;">
								<input type="radio" name="oopspam_ls_settings[connector_block_vpn_mode]" value="inherit" <?php checked( $vpn_mode, 'inherit' ); ?>>
								<?php
								if ( $inherited_vpn ) {
									esc_html_e( 'Use OOPSpam plugin setting (currently: blocking VPNs sitewide).', 'oopspam-login-shield' );
								} else {
									esc_html_e( 'Use OOPSpam plugin setting (currently: VPNs allowed sitewide).', 'oopspam-login-shield' );
								}
								?>
							</label>
							<label style="display:block;">
								<input type="radio" name="oopspam_ls_settings[connector_block_vpn_mode]" value="block" <?php checked( $vpn_mode, 'block' ); ?>>
								<?php esc_html_e( 'Always block at login (override).', 'oopspam-login-shield' ); ?>
							</label>
						</fieldset>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Block datacenter/cloud IPs', 'oopspam-login-shield' ); ?></th>
					<td>
						<fieldset>
							<legend class="screen-reader-text"><?php esc_html_e( 'Block datacenter/cloud IPs mode', 'oopspam-login-shield' ); ?></legend>
							<?php
							$dc_mode = $s['connector_block_datacenter_mode'] ?? 'inherit';
							$inherited_dc = is_array( $ipfilter_opts ) && ! empty( $ipfilter_opts['oopspam_block_cloud_providers'] );
							?>
							<label style="display:block; margin-bottom:4px;">
								<input type="radio" name="oopspam_ls_settings[connector_block_datacenter_mode]" value="inherit" <?php checked( $dc_mode, 'inherit' ); ?>>
								<?php
								if ( $inherited_dc ) {
									esc_html_e( 'Use OOPSpam plugin setting (currently: blocking datacenter IPs sitewide).', 'oopspam-login-shield' );
								} else {
									esc_html_e( 'Use OOPSpam plugin setting (currently: datacenter IPs allowed sitewide).', 'oopspam-login-shield' );
								}
								?>
							</label>
							<label style="display:block;">
								<input type="radio" name="oopspam_ls_settings[connector_block_datacenter_mode]" value="block" <?php checked( $dc_mode, 'block' ); ?>>
								<?php esc_html_e( 'Always block at login (override).', 'oopspam-login-shield' ); ?>
							</label>
						</fieldset>
						<p class="description">
							<?php esc_html_e( "AWS, Azure, GCP, OVH, DigitalOcean, etc. Disable override if you have automation logging in programmatically.", 'oopspam-login-shield' ); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Block temporary/disposable email', 'oopspam-login-shield' ); ?></th>
					<td>
						<fieldset>
							<legend class="screen-reader-text"><?php esc_html_e( 'Block temporary email mode', 'oopspam-login-shield' ); ?></legend>
							<?php
							$temp_mode = $s['connector_block_temp_email_mode'] ?? 'inherit';
							$main_opts = get_option( 'oopspamantispam_settings', array() );
							$inherited_temp = is_array( $main_opts ) && ! empty( $main_opts['oopspam_block_temp_email'] );
							?>
							<label style="display:block; margin-bottom:4px;">
								<input type="radio" name="oopspam_ls_settings[connector_block_temp_email_mode]" value="inherit" <?php checked( $temp_mode, 'inherit' ); ?>>
								<?php
								if ( $inherited_temp ) {
									esc_html_e( 'Use OOPSpam plugin setting (currently: blocking temp emails sitewide).', 'oopspam-login-shield' );
								} else {
									esc_html_e( 'Use OOPSpam plugin setting (currently: temp emails allowed sitewide).', 'oopspam-login-shield' );
								}
								?>
							</label>
							<label style="display:block;">
								<input type="radio" name="oopspam_ls_settings[connector_block_temp_email_mode]" value="block" <?php checked( $temp_mode, 'block' ); ?>>
								<?php esc_html_e( 'Always block at login (override).', 'oopspam-login-shield' ); ?>
							</label>
						</fieldset>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Country blocklist', 'oopspam-login-shield' ); ?></th>
					<td>
						<fieldset>
							<legend class="screen-reader-text"><?php esc_html_e( 'Country blocklist mode', 'oopspam-login-shield' ); ?></legend>
							<?php
							$country_mode = $s['connector_country_mode'] ?? 'inherit';

							// OOPSpam stores oopspam_countryblocklist as an
							// array (multi-select). Stringify safely for display.
							$inherited_raw = get_option( 'oopspam_countryblocklist', '' );
							if ( is_array( $inherited_raw ) ) {
								$inherited_codes = array();
								foreach ( $inherited_raw as $cc ) {
									$cc = strtoupper( trim( (string) $cc ) );
									if ( 2 === strlen( $cc ) && ctype_alpha( $cc ) ) {
										$inherited_codes[] = $cc;
									}
								}
								$inherited_list = implode( ', ', $inherited_codes );
							} else {
								$inherited_list = (string) $inherited_raw;
							}

							$inherited_label = '' !== trim( $inherited_list )
								? sprintf(
									/* translators: %s: comma-separated list of country codes */
									__( 'Use OOPSpam plugin setting (currently: %s).', 'oopspam-login-shield' ),
									$inherited_list
								)
								: __( 'Use OOPSpam plugin setting (currently: no countries blocked sitewide).', 'oopspam-login-shield' );
							?>
							<label style="display:block; margin-bottom:4px;">
								<input type="radio" name="oopspam_ls_settings[connector_country_mode]" value="inherit" <?php checked( $country_mode, 'inherit' ); ?>>
								<?php echo esc_html( $inherited_label ); ?>
							</label>
							<label style="display:block; margin-bottom:8px;">
								<input type="radio" name="oopspam_ls_settings[connector_country_mode]" value="custom" <?php checked( $country_mode, 'custom' ); ?>>
								<?php esc_html_e( 'Use a custom list at login (override below).', 'oopspam-login-shield' ); ?>
							</label>
						</fieldset>

						<label for="oopspam_ls_connector_blocked_countries" class="screen-reader-text">
							<?php esc_html_e( 'Custom country list', 'oopspam-login-shield' ); ?>
						</label>
						<textarea
							id="oopspam_ls_connector_blocked_countries"
							name="oopspam_ls_settings[connector_blocked_countries]"
							rows="3"
							cols="40"
							class="code"
							style="font-family: monospace; max-width: 320px;"
							placeholder="RU, CN, KP"
						><?php echo esc_textarea( (string) ( $s['connector_blocked_countries'] ?? '' ) ); ?></textarea>
						<p class="description">
							<?php esc_html_e( 'Two-letter ISO country codes, comma- or space-separated. Only used when "Use a custom list at login" is selected above.', 'oopspam-login-shield' ); ?>
							<a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2" target="_blank" rel="noopener"><?php esc_html_e( 'Country code reference', 'oopspam-login-shield' ); ?></a>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Require JavaScript', 'oopspam-login-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="oopspam_ls_settings[require_js]" value="1" <?php checked( ! empty( $s['require_js'] ), true ); ?>>
							<?php esc_html_e( 'Reject any login, registration, or lost-password submission that did not come from a browser running JavaScript.', 'oopspam-login-shield' ); ?>
						</label>
						<p class="description">
							<?php esc_html_e( "Most bots don't execute JavaScript, so this filters out a large slice of automated traffic before the password is even checked. Real browsers always run it, so legitimate users are unaffected. Independent of the verification widget; works even when the widget is disabled.", 'oopspam-login-shield' ); ?>
						</p>
						<p class="description" style="color:#b26900;">
							<?php esc_html_e( 'If you have any users who deliberately disable JavaScript (privacy-conscious users using NoScript, Tor browsers, etc.) they will be unable to log in.', 'oopspam-login-shield' ); ?>
						</p>
					</td>
				</tr>

			</table>

			<h2 class="title" style="margin-top:32px;"><?php esc_html_e( 'Limit login attempts', 'oopspam-login-shield' ); ?></h2>
			<p style="max-width:760px;">
				<?php esc_html_e( 'Track failed logins per-IP and lock out brute-force attackers. Lockouts apply before the password is even validated, so an attacker can\'t keep guessing.', 'oopspam-login-shield' ); ?>
			</p>

			<table class="form-table" role="presentation">

				<tr>
					<th scope="row"><?php esc_html_e( 'Enable limit login attempts', 'oopspam-login-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="oopspam_ls_settings[lla_enabled]" value="1" <?php checked( ! empty( $s['lla_enabled'] ), true ); ?>>
							<?php esc_html_e( 'Track failed logins and apply automatic lockouts.', 'oopspam-login-shield' ); ?>
						</label>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Lockout rules', 'oopspam-login-shield' ); ?></th>
					<td>
						<p style="margin:0 0 10px 0; max-width:760px;">
							<?php
							echo wp_kses(
								sprintf(
									/* translators: 1: failed-attempts input, 2: minutes input */
									__( 'After %1$s failed login attempts within the rolling window, lock the IP out for %2$s minutes.', 'oopspam-login-shield' ),
									'<input type="number" min="2" max="50" step="1" name="oopspam_ls_settings[lla_max_attempts]" value="' . esc_attr( (int) $s['lla_max_attempts'] ) . '" style="width:70px;">',
									'<input type="number" min="1" max="720" step="1" name="oopspam_ls_settings[lla_lockout_minutes]" value="' . esc_attr( (int) $s['lla_lockout_minutes'] ) . '" style="width:80px;">'
								),
								array( 'input' => array( 'type' => true, 'min' => true, 'max' => true, 'step' => true, 'name' => true, 'value' => true, 'style' => true ) )
							);
							?>
						</p>
						<p style="margin:0; max-width:760px;">
							<?php
							echo wp_kses(
								sprintf(
									/* translators: 1: lockout-count input, 2: hours input */
									__( 'After %1$s lockouts in 24 hours, block further attempts from that IP for %2$s hours.', 'oopspam-login-shield' ),
									'<input type="number" min="1" max="20" step="1" name="oopspam_ls_settings[lla_max_lockouts]" value="' . esc_attr( (int) $s['lla_max_lockouts'] ) . '" style="width:70px;">',
									'<input type="number" min="1" max="168" step="1" name="oopspam_ls_settings[lla_long_hours]" value="' . esc_attr( (int) $s['lla_long_hours'] ) . '" style="width:80px;">'
								),
								array( 'input' => array( 'type' => true, 'min' => true, 'max' => true, 'step' => true, 'name' => true, 'value' => true, 'style' => true ) )
							);
							?>
						</p>
						<p class="description" style="margin-top:10px;">
							<?php esc_html_e( 'Lockouts apply per-IP. Successful logins do not reset the failed-attempt counter. It ages out naturally over the rolling window.', 'oopspam-login-shield' ); ?>
							<?php
							echo wp_kses_post(
								sprintf(
									/* translators: %s: link to log tab */
									__( 'See active lockouts and recent activity on the %s.', 'oopspam-login-shield' ),
									'<a href="' . esc_url( $this->tab_url( 'log' ) ) . '">' . esc_html__( 'Login Log tab', 'oopspam-login-shield' ) . '</a>'
								)
							);
							?>
						</p>
					</td>
				</tr>

			</table>

			<h2 class="title" style="margin-top:32px;"><?php esc_html_e( 'Auto-block honeypot logins', 'oopspam-login-shield' ); ?></h2>
			<p style="max-width:760px;">
				<?php esc_html_e( "Some usernames or emails are never going to be typed by a real user on your site. Bots try them constantly. Add them here and any IP that submits one will be blocked immediately, no warning or threshold counting required.", 'oopspam-login-shield' ); ?>
			</p>
			<p style="max-width:760px;">
				<?php esc_html_e( "This is especially useful when you only allow email login but bots keep trying bare usernames like 'admin'. Without honeypot blocking, those failed attempts log against the username field and may not trigger the per-IP threshold quickly enough.", 'oopspam-login-shield' ); ?>
			</p>

			<table class="form-table" role="presentation">

				<tr>
					<th scope="row"><?php esc_html_e( 'Enable honeypot blocking', 'oopspam-login-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="oopspam_ls_settings[lla_honeypot_enabled]" value="1" <?php checked( ! empty( $s['lla_honeypot_enabled'] ), true ); ?>>
							<?php esc_html_e( 'Auto-block any IP that tries one of the honeypot logins below.', 'oopspam-login-shield' ); ?>
						</label>
						<p class="description">
							<?php esc_html_e( 'Requires Limit Login Attempts to be enabled above.', 'oopspam-login-shield' ); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row">
						<label for="oopspam_ls_lla_honeypot_logins">
							<?php esc_html_e( 'Honeypot usernames and emails', 'oopspam-login-shield' ); ?>
						</label>
					</th>
					<td>
						<textarea
							id="oopspam_ls_lla_honeypot_logins"
							name="oopspam_ls_settings[lla_honeypot_logins]"
							rows="10"
							cols="50"
							class="large-text code"
							style="font-family: monospace;"
							placeholder="admin&#10;administrator&#10;admin@*&#10;info@*"
						><?php echo esc_textarea( (string) ( $s['lla_honeypot_logins'] ?? '' ) ); ?></textarea>
						<p class="description">
							<?php esc_html_e( 'One entry per line. Three formats are supported:', 'oopspam-login-shield' ); ?>
						</p>
						<ul style="margin: 4px 0 8px 22px; list-style: disc; font-size: 13px; color: #50575e;">
							<li>
								<code>admin</code>
								<?php esc_html_e( 'Plain username. Case-insensitive exact match.', 'oopspam-login-shield' ); ?>
							</li>
							<li>
								<code>admin@example.com</code>
								<?php esc_html_e( 'Full email. Exact match.', 'oopspam-login-shield' ); ?>
							</li>
							<li>
								<code>admin@*</code>
								<?php esc_html_e( "Wildcard. Matches admin@anything.com, and also catches a bot that just types 'admin' alone.", 'oopspam-login-shield' ); ?>
							</li>
						</ul>
						<p class="description">
							<?php esc_html_e( 'Lines starting with # are treated as comments. The list is case-insensitive.', 'oopspam-login-shield' ); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row">
						<label for="oopspam_ls_lla_honeypot_hours">
							<?php esc_html_e( 'Block duration', 'oopspam-login-shield' ); ?>
						</label>
					</th>
					<td>
						<input
							type="number"
							id="oopspam_ls_lla_honeypot_hours"
							name="oopspam_ls_settings[lla_honeypot_hours]"
							value="<?php echo esc_attr( (int) ( $s['lla_honeypot_hours'] ?? 24 ) ); ?>"
							min="1" max="720" step="1"
							style="width:80px;"
						>
						<?php esc_html_e( 'hours', 'oopspam-login-shield' ); ?>
						<p class="description">
							<?php esc_html_e( 'How long to block an IP that trips the honeypot. 24 hours is the default and works well for most sites.', 'oopspam-login-shield' ); ?>
						</p>
					</td>
				</tr>

			</table>

			<?php submit_button(); ?>
		</form>

		<hr>

		<h2><?php esc_html_e( 'Preview', 'oopspam-login-shield' ); ?></h2>
		<p>
			<?php
			echo wp_kses_post(
				sprintf(
					/* translators: %s: link to wp-login.php */
					__( 'Open your %s in a private/incognito window to see the widget in action. (Logged-in administrators are still required to verify.)', 'oopspam-login-shield' ),
					'<a href="' . esc_url( $login_url ) . '" target="_blank" rel="noopener">' . esc_html__( 'login page', 'oopspam-login-shield' ) . '</a>'
				)
			);
			?>
		</p>
		<?php
	}

	/* -----------------------------------------------------------------------
	 * Log tab — aggregated per-IP "Failed login attempts" table.
	 * --------------------------------------------------------------------- */


	private function render_log_tab(): void {
		$s = oopspam_ls_get_settings();

		// Notices from admin-post redirects.
		if ( isset( $_GET['unlocked'] ) && '1' === (string) $_GET['unlocked'] ) {
			echo '<div class="notice notice-success is-dismissible"><p>'
				. esc_html__( 'IP unlocked.', 'oopspam-login-shield' )
				. '</p></div>';
		}
		if ( isset( $_GET['cleared'] ) && '1' === (string) $_GET['cleared'] ) {
			echo '<div class="notice notice-success is-dismissible"><p>'
				. esc_html__( 'Log cleared.', 'oopspam-login-shield' )
				. '</p></div>';
		}
		if ( isset( $_GET['repaired'] ) && '1' === (string) $_GET['repaired'] ) {
			$msg = OOPSpam_LS_LLA_Store::table_exists()
				? __( 'Log table is ready. Try a wrong-password login from another browser to confirm logging works.', 'oopspam-login-shield' )
				: __( 'Could not create the log table. Check the diagnostic info below.', 'oopspam-login-shield' );
			$type = OOPSpam_LS_LLA_Store::table_exists() ? 'success' : 'error';
			echo '<div class="notice notice-' . esc_attr( $type ) . ' is-dismissible"><p>' . esc_html( $msg ) . '</p></div>';
		}

		if ( empty( $s['lla_enabled'] ) ) {
			echo '<div class="notice notice-warning inline"><p>'
				. wp_kses_post(
					sprintf(
						/* translators: %s: link to settings tab */
						__( 'Limit Login Attempts is currently disabled. New events will not be recorded until you enable it on the %s.', 'oopspam-login-shield' ),
						'<a href="' . esc_url( $this->tab_url( 'settings' ) ) . '">' . esc_html__( 'Settings tab', 'oopspam-login-shield' ) . '</a>'
					)
				)
				. '</p></div>';
		}

		// --- Diagnostics + reactivate panel (always shown) -----------------
		$this->render_log_diagnostics( $s );

		// --- Active lockouts -----------------------------------------------
		$lockouts = OOPSpam_LS_LLA_Store::get_lockouts();
		if ( ! empty( $lockouts ) ) :
			?>
			<h2 style="margin-top:24px;"><?php esc_html_e( 'Active lockouts', 'oopspam-login-shield' ); ?></h2>
			<table class="widefat striped" style="max-width:900px;">
				<thead>
					<tr>
						<th><?php esc_html_e( 'IP Address', 'oopspam-login-shield' ); ?></th>
						<th><?php esc_html_e( 'Locked Until', 'oopspam-login-shield' ); ?></th>
						<th><?php esc_html_e( 'Time Remaining', 'oopspam-login-shield' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'oopspam-login-shield' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php
					arsort( $lockouts );
					foreach ( $lockouts as $ip => $expires_ts ) :
						$expires_mysql = gmdate( 'Y-m-d H:i:s', (int) $expires_ts );
						?>
						<tr>
							<td><code><?php echo esc_html( $ip ); ?></code></td>
							<td><?php echo esc_html( $this->format_local_time( $expires_mysql ) ); ?></td>
							<td><?php echo esc_html( human_time_diff( time(), (int) $expires_ts ) ); ?></td>
							<td>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
									<input type="hidden" name="action" value="oopspam_ls_unlock">
									<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>">
									<?php wp_nonce_field( self::NONCE_UNLOCK ); ?>
									<button type="submit" class="button button-small">
										<?php esc_html_e( 'Release Lock', 'oopspam-login-shield' ); ?>
									</button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<?php
		endif;

		// --- Login attempts table -------------------------------------------
		$per_page = 25;
		$paged    = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
		$offset   = ( $paged - 1 ) * $per_page;
		$total    = OOPSpam_LS_LLA_Store::get_total();
		$entries  = OOPSpam_LS_LLA_Store::get_entries( $per_page, $offset );
		$pages    = max( 1, (int) ceil( $total / $per_page ) );
		?>

		<h2 style="margin-top:32px;">
			<?php esc_html_e( 'Login attempts', 'oopspam-login-shield' ); ?>
			<span style="font-weight:400; color:#646970;">
				(<?php echo esc_html( number_format_i18n( $total ) ); ?>)
			</span>
		</h2>

		<?php if ( empty( $entries ) ) : ?>
			<p><em><?php esc_html_e( 'No login attempts have been recorded yet.', 'oopspam-login-shield' ); ?></em></p>
		<?php else : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th style="width:200px;"><?php esc_html_e( 'Time', 'oopspam-login-shield' ); ?></th>
						<th style="width:160px;"><?php esc_html_e( 'IP Address', 'oopspam-login-shield' ); ?></th>
						<th><?php esc_html_e( 'Username / Email', 'oopspam-login-shield' ); ?></th>
						<th style="width:100px;"><?php esc_html_e( 'Result', 'oopspam-login-shield' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $entries as $e ) : ?>
						<tr>
							<td>
								<?php echo esc_html( $this->format_local_time( $e->created_at ) ); ?>
								<div style="color:#646970; font-size:11px;">
									<?php
									printf(
										/* translators: %s: time difference */
										esc_html__( '%s ago', 'oopspam-login-shield' ),
										esc_html( human_time_diff( strtotime( $e->created_at . ' UTC' ), time() ) )
									);
									?>
								</div>
							</td>
							<td><code><?php echo esc_html( $e->ip ); ?></code></td>
							<td><?php echo '' !== (string) $e->username ? esc_html( $e->username ) : '<span style="color:#646970;">&mdash;</span>'; ?></td>
							<td>
								<?php if ( (int) $e->success === 1 ) : ?>
									<span style="color:#1a7e1a; font-weight:600;">&#x2713; <?php esc_html_e( 'Success', 'oopspam-login-shield' ); ?></span>
								<?php else : ?>
									<span style="color:#b32d2e; font-weight:600;">&#x2717; <?php esc_html_e( 'Failed', 'oopspam-login-shield' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $pages > 1 ) : ?>
				<div class="tablenav" style="margin-top:12px;">
					<div class="tablenav-pages">
						<span class="displaying-num">
							<?php
							echo esc_html(
								sprintf(
									/* translators: 1: current page, 2: total pages */
									__( 'Page %1$d of %2$d', 'oopspam-login-shield' ),
									$paged,
									$pages
								)
							);
							?>
						</span>
						<?php
						echo paginate_links(
							array(
								'base'      => add_query_arg( 'paged', '%#%', $this->tab_url( 'log' ) ),
								'format'    => '',
								'prev_text' => '&laquo;',
								'next_text' => '&raquo;',
								'total'     => $pages,
								'current'   => $paged,
							)
						);
						?>
					</div>
				</div>
			<?php endif; ?>
		<?php endif; ?>

		<hr style="margin-top:32px;">
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
			onsubmit="return confirm('<?php echo esc_js( __( 'Permanently delete all log entries? This cannot be undone.', 'oopspam-login-shield' ) ); ?>');">
			<input type="hidden" name="action" value="oopspam_ls_clear_log">
			<?php wp_nonce_field( self::NONCE_CLEAR_LOG ); ?>
			<button type="submit" class="button button-secondary">
				<?php esc_html_e( 'Clear log', 'oopspam-login-shield' ); ?>
			</button>
			<span class="description" style="margin-left:8px;">
				<?php esc_html_e( 'Old entries are auto-purged after 30 days.', 'oopspam-login-shield' ); ?>
			</span>
		</form>
		<?php
	}

	/**
	 * Diagnostic + reactivate panel for the Log tab.
	 *
	 * Shows the actual state of the moving parts (table exists, hooks
	 * registered, entries recorded) and gives admins a one-click reactivate
	 * button that re-runs install + clears any stuck install-failed flag.
	 *
	 * Always rendered — folded into a <details> when everything is healthy
	 * so it doesn't dominate the tab during normal use, but expanded when
	 * something is broken so the admin can see what to fix.
	 */
	private function render_log_diagnostics( array $settings ): void {
		$table_ok       = OOPSpam_LS_LLA_Store::table_exists();
		$total_in_log   = $table_ok ? OOPSpam_LS_LLA_Store::get_total() : 0;
		$db_install_err = get_option( 'oopspam_ls_db_install_failed' );
		$has_failed_hook = has_action( 'wp_login_failed' );
		$has_auth_hook   = has_filter( 'wp_authenticate_user' );
		$hooks_ok       = $has_failed_hook && $has_auth_hook;

		$everything_ok = $table_ok && $hooks_ok && ! $db_install_err && ! empty( $settings['lla_enabled'] );

		// Auto-expand when something's wrong.
		$open_attr = $everything_ok ? '' : ' open';

		$reactivate_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=oopspam_ls_reactivate_lla' ),
			'oopspam_ls_reactivate_lla'
		);
		?>
		<details<?php echo $open_attr; ?> style="margin-top:16px; padding:12px 16px; background:#fff; border:1px solid #c3c4c7; border-radius:4px;">
			<summary style="cursor:pointer; font-weight:600;">
				<?php
				if ( $everything_ok ) {
					echo '<span style="color:#1a7e1a;">&#x2713;</span> ';
					esc_html_e( 'Logging diagnostics: all systems normal', 'oopspam-login-shield' );
				} else {
					echo '<span style="color:#b32d2e;">&#x26A0;</span> ';
					esc_html_e( 'Logging diagnostics: needs attention', 'oopspam-login-shield' );
				}
				?>
			</summary>
			<ul style="margin:12px 0 0 18px; list-style:disc; line-height:1.6;">
				<li>
					<?php esc_html_e( 'Limit Login Attempts feature:', 'oopspam-login-shield' ); ?>
					<?php
					echo ! empty( $settings['lla_enabled'] )
						? '<span style="color:#1a7e1a;">&#x2713; ' . esc_html__( 'enabled', 'oopspam-login-shield' ) . '</span>'
						: '<span style="color:#b32d2e;">&#x2717; ' . esc_html__( 'DISABLED on Settings tab', 'oopspam-login-shield' ) . '</span>';
					?>
				</li>
				<li>
					<?php esc_html_e( 'Log database table:', 'oopspam-login-shield' ); ?>
					<?php
					echo $table_ok
						? '<span style="color:#1a7e1a;">&#x2713; ' . esc_html__( 'exists', 'oopspam-login-shield' ) . '</span>'
						: '<span style="color:#b32d2e;">&#x2717; ' . esc_html__( 'MISSING', 'oopspam-login-shield' ) . '</span>';
					?>
					<code style="font-size:11px; color:#646970;"><?php echo esc_html( OOPSpam_LS_LLA_Store::table() ); ?></code>
				</li>
				<li>
					<?php esc_html_e( 'wp_login_failed hook:', 'oopspam-login-shield' ); ?>
					<?php
					echo $has_failed_hook
						? '<span style="color:#1a7e1a;">&#x2713; ' . esc_html__( 'registered', 'oopspam-login-shield' ) . '</span>'
						: '<span style="color:#b32d2e;">&#x2717; ' . esc_html__( 'NOT registered', 'oopspam-login-shield' ) . '</span>';
					?>
				</li>
				<li>
					<?php esc_html_e( 'wp_authenticate_user hook:', 'oopspam-login-shield' ); ?>
					<?php
					echo $has_auth_hook
						? '<span style="color:#1a7e1a;">&#x2713; ' . esc_html__( 'registered', 'oopspam-login-shield' ) . '</span>'
						: '<span style="color:#b32d2e;">&#x2717; ' . esc_html__( 'NOT registered', 'oopspam-login-shield' ) . '</span>';
					?>
				</li>
				<li>
					<?php esc_html_e( 'Total entries in log:', 'oopspam-login-shield' ); ?>
					<strong><?php echo esc_html( number_format_i18n( $total_in_log ) ); ?></strong>
				</li>
				<?php if ( is_array( $db_install_err ) && ! empty( $db_install_err['error'] ) ) : ?>
					<li style="color:#b32d2e;">
						<?php esc_html_e( 'Last DB install error:', 'oopspam-login-shield' ); ?>
						<code style="font-size:11px;"><?php echo esc_html( $db_install_err['error'] ); ?></code>
					</li>
				<?php endif; ?>
			</ul>

			<p style="margin:14px 0 0 0;">
				<a href="<?php echo esc_url( $reactivate_url ); ?>" class="button button-primary">
					<?php esc_html_e( 'Reactivate logging', 'oopspam-login-shield' ); ?>
				</a>
				<span style="margin-left:10px; color:#646970; font-size:13px;">
					<?php esc_html_e( "Re-runs the activation routine: re-creates the log table if missing and re-registers hooks. Safe to click anytime. It won't delete any data.", 'oopspam-login-shield' ); ?>
				</span>
			</p>
		</details>
		<?php
	}

	/* -----------------------------------------------------------------------
	 * About tab
	 * --------------------------------------------------------------------- */

	private function render_about_tab(): void {
		$has_oop = ( function_exists( 'oopspam_check_spam' ) || function_exists( 'oopspamantispam_call_OOPSpam' ) )
			&& function_exists( 'oopspamantispam_get_key' );
		?>
		<div style="max-width:760px;">

			<div class="notice notice-info inline" style="padding:14px 16px; margin-top:0;">
				<p style="margin:0; font-size:14px; line-height:1.5;">
					<strong><?php esc_html_e( 'Unofficial connector plugin', 'oopspam-login-shield' ); ?></strong>
					<?php esc_html_e( 'by', 'oopspam-login-shield' ); ?>
					<a href="https://nahnuplugins.com/" target="_blank" rel="noopener">Nahnu Plugins</a>.
					<?php esc_html_e( 'Not affiliated with or endorsed by OOPSpam. This is a community-built integration that extends their official plugin.', 'oopspam-login-shield' ); ?>
				</p>
			</div>

			<h2><?php esc_html_e( 'About OOPSpam', 'oopspam-login-shield' ); ?></h2>
			<p>
				<?php esc_html_e( 'OOPSpam is a third-party anti-spam service. All of the actual spam-detection capability used by this plugin (IP reputation, content classification, VPN/datacenter detection, country rules, blocklists, rate limiting) comes from OOPSpam\'s API and their official WordPress plugin.', 'oopspam-login-shield' ); ?>
			</p>
			<ul style="list-style:disc; margin-left:22px;">
				<li><a href="https://www.oopspam.com/" target="_blank" rel="noopener"><?php esc_html_e( 'OOPSpam website', 'oopspam-login-shield' ); ?></a></li>
				<li><a href="https://wordpress.org/plugins/oopspam-anti-spam/" target="_blank" rel="noopener"><?php esc_html_e( 'OOPSpam Anti-Spam plugin (WordPress.org)', 'oopspam-login-shield' ); ?></a></li>
				<li><a href="https://www.oopspam.com/docs" target="_blank" rel="noopener"><?php esc_html_e( 'OOPSpam documentation', 'oopspam-login-shield' ); ?></a></li>
				<li><a href="https://www.oopspam.com/docs/api" target="_blank" rel="noopener"><?php esc_html_e( 'OOPSpam API reference', 'oopspam-login-shield' ); ?></a></li>
				<li><a href="https://www.oopspam.com/pricing" target="_blank" rel="noopener"><?php esc_html_e( 'OOPSpam pricing & API plans', 'oopspam-login-shield' ); ?></a></li>
				<?php if ( $has_oop ) : ?>
					<li>
						<a href="<?php echo esc_url( admin_url( 'options-general.php?page=oopspamantispam' ) ); ?>">
							<?php esc_html_e( 'OOPSpam settings on this site', 'oopspam-login-shield' ); ?>
						</a>
					</li>
				<?php endif; ?>
			</ul>

			<h2 style="margin-top:32px;"><?php esc_html_e( 'About this plugin', 'oopspam-login-shield' ); ?></h2>
			<p>
				<?php esc_html_e( 'OOPSpam Login Shield adds login-page protection on top of the official OOPSpam Anti-Spam plugin. It calls OOPSpam\'s public API for bot and spam detection, and adds its own token verification, brute-force lockouts, and audit log. Blocked and successful login attempts are written to OOPSpam\'s standard Spam and Ham Entries tables under a stable form ID, so admins can review them alongside everything else OOPSpam handles.', 'oopspam-login-shield' ); ?>
			</p>
			<p>
				<?php esc_html_e( 'It also includes optional honeypot blocking: list usernames or emails that real users would never type (admin, root, info@your-domain) and any IP that tries one is blocked instantly for 24 hours. This is especially useful for sites that only allow email login but get hit with bots trying bare usernames.', 'oopspam-login-shield' ); ?>
			</p>
			<ul style="list-style:disc; margin-left:22px;">
				<li><a href="https://nahnuplugins.com/" target="_blank" rel="noopener"><?php esc_html_e( 'Nahnu Plugins', 'oopspam-login-shield' ); ?></a></li>
				<li><a href="https://github.com/jaimealnassim/oopspam-login-shield" target="_blank" rel="noopener"><?php esc_html_e( 'Source code on GitHub', 'oopspam-login-shield' ); ?></a></li>
				<li><a href="https://github.com/jaimealnassim/oopspam-login-shield/issues" target="_blank" rel="noopener"><?php esc_html_e( 'Report a bug or request a feature', 'oopspam-login-shield' ); ?></a></li>
			</ul>

			<h2 style="margin-top:32px;"><?php esc_html_e( 'Data retention', 'oopspam-login-shield' ); ?></h2>
			<p>
				<?php esc_html_e( 'Login attempts (IP address, submitted username or email, success or failure, and timestamp) are stored in your own WordPress database. They are kept for 30 days and then deleted automatically by a daily WordPress cron job. Nothing is sent to a third party for the limit-login-attempts feature; this data never leaves your site.', 'oopspam-login-shield' ); ?>
			</p>
			<p>
				<?php esc_html_e( 'You can also clear the entire log at any time from the Login Log tab. The retention period can be customized in code with the oopspam_ls_lla_log_retention_days filter if you need a longer or shorter window for your compliance requirements.', 'oopspam-login-shield' ); ?>
			</p>
			<p>
				<?php esc_html_e( 'Lockout state is stored in a separate WordPress option and clears itself automatically when each lockout expires. Releasing a lock manually from the Login Log tab simply removes that IP from the lockout list; the visitor can then attempt to log in again.', 'oopspam-login-shield' ); ?>
			</p>
			<p>
				<?php esc_html_e( 'Note: this is separate from any data sent to OOPSpam by the verification widget. OOPSpam\'s data handling is governed by their own privacy policy.', 'oopspam-login-shield' ); ?>
			</p>

			<h2 style="margin-top:32px;"><?php esc_html_e( 'Credits', 'oopspam-login-shield' ); ?></h2>
			<p>
				<?php esc_html_e( 'OOPSpam and the OOPSpam Anti-Spam plugin are products of OOPSpam. All credit for the underlying spam-detection capability goes to them; this plugin merely extends their public API. The widget UX is inspired by Altcha\'s checkbox-style verification.', 'oopspam-login-shield' ); ?>
			</p>
			<p>
				<?php esc_html_e( 'The Limit Login Attempts module is included as a lightweight alternative to a dedicated plugin (such as Limit Login Attempts Reloaded or WP Limit Login Attempts). It is intentionally minimal: IP-based lockouts, an audit log, and manual unlock. This way, admins who only need that level of brute-force protection don\'t have to install a second plugin alongside this one. If you need richer features (allowlists, country blocks, GDPR-compliant pseudonymisation, cluster sync), a dedicated plugin will serve you better.', 'oopspam-login-shield' ); ?>
			</p>

			<h2 style="margin-top:32px;"><?php esc_html_e( 'Version', 'oopspam-login-shield' ); ?></h2>
			<p>
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: plugin version, 2: PHP version */
						__( 'OOPSpam Login Shield v%1$s, running on PHP %2$s', 'oopspam-login-shield' ),
						OOPSPAM_LS_VERSION,
						PHP_VERSION
					)
				);
				?>
			</p>

		</div>
		<?php
	}

	/* -----------------------------------------------------------------------
	 * admin-post.php handlers
	 * --------------------------------------------------------------------- */

	public function handle_unlock(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'oopspam-login-shield' ), 403 );
		}
		check_admin_referer( self::NONCE_UNLOCK );

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( '' !== $ip ) {
			OOPSpam_LS_LLA_Store::clear_lockout( $ip );
		}

		wp_safe_redirect(
			add_query_arg(
				array( 'unlocked' => 1 ),
				$this->tab_url( 'log' )
			)
		);
		exit;
	}

	public function handle_clear_log(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'oopspam-login-shield' ), 403 );
		}
		check_admin_referer( self::NONCE_CLEAR_LOG );

		OOPSpam_LS_LLA_Store::clear_all();

		wp_safe_redirect(
			add_query_arg(
				array( 'cleared' => 1 ),
				$this->tab_url( 'log' )
			)
		);
		exit;
	}

	/**
	 * "Reactivate logging" — re-runs the install routine. Safe to click any
	 * time; only does work if the table is missing or schema-version mismatched.
	 */
	public function handle_reactivate(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'oopspam-login-shield' ), 403 );
		}
		check_admin_referer( 'oopspam_ls_reactivate_lla' );

		OOPSpam_LS_LLA_Store::install();

		wp_safe_redirect(
			add_query_arg(
				array( 'repaired' => 1 ),
				$this->tab_url( 'log' )
			)
		);
		exit;
	}

	/* -----------------------------------------------------------------------
	 * Helpers
	 * --------------------------------------------------------------------- */

	/**
	 * Convert a UTC MySQL datetime to the site's local time, in the user's
	 * preferred date+time format.
	 */
	private function format_local_time( ?string $utc_mysql ): string {
		if ( ! $utc_mysql ) {
			return '';
		}
		$ts = strtotime( $utc_mysql . ' UTC' );
		if ( ! $ts ) {
			return $utc_mysql;
		}
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts );
	}
}
