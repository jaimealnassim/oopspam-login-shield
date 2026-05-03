<?php
/**
 * Hooks into the wp-login.php forms to render the Altcha-style widget
 * and enforce token + final OOPSpam validation on submission.
 *
 * @package OOPSpam_Login_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOPSpam_LS_Login_Protector {

	public function __construct() {
		// Render widget on each form.
		add_action( 'login_form',        $this->render_widget( ... ) );
		add_action( 'register_form',     $this->render_widget( ... ) );
		add_action( 'lostpassword_form', $this->render_widget( ... ) );

		// Enqueue assets only on the login page.
		add_action( 'login_enqueue_scripts', $this->enqueue( ... ) );

		// Validation hooks.
		add_filter( 'authenticate',        $this->authenticate( ... ),       30, 3 );
		add_filter( 'registration_errors', $this->registration_errors( ... ), 5, 3 );
		add_action( 'lostpassword_post',   $this->lostpassword_post( ... ),  10, 1 );
	}

	/**
	 * Determine whether we should act on the current login-screen action.
	 *
	 * @return bool
	 */
	private function should_protect_current_form() {
		$settings = oopspam_ls_get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return false;
		}

		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$map = array(
			'login'            => 'protect_login',
			'register'         => 'protect_register',
			'lostpassword'     => 'protect_lostpassword',
			'retrievepassword' => 'protect_lostpassword',
		);

		if ( ! isset( $map[ $action ] ) ) {
			return false;
		}

		return ! empty( $settings[ $map[ $action ] ] );
	}

	/**
	 * Enqueue widget JS/CSS on the login screen.
	 */
	public function enqueue() {
		if ( ! $this->should_protect_current_form() ) {
			return;
		}

		wp_enqueue_style(
			'oopspam-ls',
			OOPSPAM_LS_URL . 'assets/widget.css',
			array(),
			OOPSPAM_LS_VERSION
		);

		wp_enqueue_script(
			'oopspam-ls',
			OOPSPAM_LS_URL . 'assets/widget.js',
			array(),
			OOPSPAM_LS_VERSION,
			true
		);

		$settings = oopspam_ls_get_settings();

		wp_localize_script(
			'oopspam-ls',
			'OOPSpamLS',
			array(
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'nonce'      => wp_create_nonce( OOPSpam_LS_Ajax::NONCE ),
				'autoVerify' => ! empty( $settings['auto_verify'] ),
				'i18n'       => array(
					'idle'      => __( "I'm not a robot", 'oopspam-login-shield' ),
					'verifying' => __( 'Verifying…', 'oopspam-login-shield' ),
					'verified'  => __( 'Verified', 'oopspam-login-shield' ),
					'failed'    => ! empty( $settings['fail_message'] )
						? $settings['fail_message']
						: __( 'Verification failed. Click to retry.', 'oopspam-login-shield' ),
					'wait'      => __( 'Please wait for verification to finish.', 'oopspam-login-shield' ),
				),
			)
		);
	}

	/**
	 * Render the Altcha-style widget markup inside the form.
	 */
	public function render_widget() {
		if ( ! $this->should_protect_current_form() ) {
			return;
		}
		?>
		<div id="oopspam-ls-widget" class="oolsh-widget" data-state="idle">
			<div class="oolsh-checkbox" role="checkbox" aria-checked="false" tabindex="0" aria-labelledby="oolsh-label">
				<span class="oolsh-spinner" aria-hidden="true"></span>
				<svg class="oolsh-check" viewBox="0 0 14 14" aria-hidden="true">
					<path d="M2 7.5 L5.5 11 L12 3" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
				<svg class="oolsh-x" viewBox="0 0 14 14" aria-hidden="true">
					<path d="M3 3 L11 11 M11 3 L3 11" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/>
				</svg>
			</div>
			<div class="oolsh-text">
				<span id="oolsh-label" class="oolsh-label"><?php esc_html_e( "I'm not a robot", 'oopspam-login-shield' ); ?></span>
				<span class="oolsh-brand">
					<?php esc_html_e( 'Protected by', 'oopspam-login-shield' ); ?>
					<a href="https://www.oopspam.com/" target="_blank" rel="noopener noreferrer">OOPSpam</a>
				</span>
			</div>
			<input type="hidden" name="oopspam_ls_token" id="oopspam-ls-token" value="" />
		</div>
		<?php
	}

	/**
	 * Validate on login (priority 30 → after wp_authenticate_username_password at 20).
	 *
	 * @param WP_User|WP_Error|null $user
	 * @param string                $username
	 * @param string                $password
	 * @return WP_User|WP_Error|null
	 */
	public function authenticate( $user, $username, $password ) {
		// If a previous filter already returned an error, leave it alone.
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$settings = oopspam_ls_get_settings();
		if ( empty( $settings['enabled'] ) || empty( $settings['protect_login'] ) ) {
			return $user;
		}

		// Skip non-form auth (XML-RPC, REST, programmatic).
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return $user;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return $user;
		}

		// Only enforce on the wp-login.php form post — keys 'log' and 'pwd' are WP's form fields.
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$is_form_post = isset( $_POST['log'] ) || isset( $_POST['pwd'] ) || isset( $_POST['oopspam_ls_token'] );
		// phpcs:enable
		if ( ! $is_form_post ) {
			return $user;
		}

		// Empty username/password — let WP raise its own native error.
		if ( empty( $username ) ) {
			return $user;
		}

		// Validate token.
		$token = isset( $_POST['oopspam_ls_token'] )
			? sanitize_text_field( wp_unslash( $_POST['oopspam_ls_token'] ) )
			: '';

		$check = OOPSpam_LS_Token::validate( $token );
		if ( is_wp_error( $check ) ) {
			return new WP_Error(
				'oopspam_ls_unverified',
				'<strong>' . esc_html__( 'Error:', 'oopspam-login-shield' ) . '</strong> ' . esc_html( $check->get_error_message() )
			);
		}

		// Final OOPSpam check with the actual username/email.
		//
		// Skip this if the OOPSpam parent plugin (1.2.68+) is already running
		// its own login-time check. Doing both means double API quota and
		// double the chance of a false-positive lockout. Their integration
		// covers the same ground we used to: runs the check on submit, with
		// the actual username/email, before the password is validated. Our
		// value-add (token verification, LLA module, honeypot, audit log)
		// stays intact either way.
		$oopspam_handles_it = function_exists( 'oopspam_ls_oopspam_handles_login' )
			&& oopspam_ls_oopspam_handles_login();

		if ( ! $oopspam_handles_it && oopspam_ls_is_oopspam_ready() ) {
			$email = is_email( $username ) ? $username : '';
			$ip    = oopspam_ls_get_ip();

			// Sentinel content > 20 chars — also serves as the description shown
			// in OOPSpam's admin entries table when blocked logins are reviewed.
			// Username is escaped for safety since it ends up rendered in the admin.
			$safe_username = sanitize_user( wp_unslash( (string) $username ), false );
			$content       = sprintf(
				'OOPSpam Login Shield: login attempt as "%s".',
				$safe_username
			);

			// log: true — we WANT blocked logins (and successful ones) to appear
			// in OOPSpam's Spam/Ham Entries tables so admins can audit.
			$result = oopspam_ls_run_check(
				$ip,
				$email,
				$content,
				array(
					'log'      => true,
					'form_id'  => 'oopspam-login-shield-login',
					'raw_data' => wp_json_encode( array( 'username' => $safe_username ) ),
				)
			);

			if ( is_array( $result ) && true === $result['isSpam'] ) {
				$msg = ! empty( $settings['spam_message'] )
					? $settings['spam_message']
					: __( 'Your sign-in attempt was blocked as suspicious.', 'oopspam-login-shield' );

				/**
				 * Fires when a login attempt is blocked.
				 *
				 * @param string $username Submitted username/email.
				 * @param string $ip       Detected sender IP.
				 * @param array  $result   Normalised OOPSpam result array.
				 */
				do_action( 'oopspam_ls_login_blocked', $username, $ip, $result );

				return new WP_Error(
					'oopspam_ls_blocked',
					'<strong>' . esc_html__( 'Error:', 'oopspam-login-shield' ) . '</strong> ' . esc_html( $msg )
				);
			}
		}

		return $user;
	}

	/**
	 * Validate on registration. We run BEFORE the parent OOPSpam plugin (priority 5)
	 * so that bot submissions without a token fail fast and don't burn API quota.
	 *
	 * @param WP_Error $errors
	 * @param string   $sanitized_user_login
	 * @param string   $user_email
	 * @return WP_Error
	 */
	public function registration_errors( $errors, $sanitized_user_login, $user_email ) {
		$settings = oopspam_ls_get_settings();
		if ( empty( $settings['enabled'] ) || empty( $settings['protect_register'] ) ) {
			return $errors;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$token = isset( $_POST['oopspam_ls_token'] )
			? sanitize_text_field( wp_unslash( $_POST['oopspam_ls_token'] ) )
			: '';
		// phpcs:enable

		$check = OOPSpam_LS_Token::validate( $token );
		if ( is_wp_error( $check ) ) {
			$errors->add(
				'oopspam_ls_unverified',
				'<strong>' . esc_html__( 'Error:', 'oopspam-login-shield' ) . '</strong> ' . esc_html( $check->get_error_message() )
			);
		}
		return $errors;
	}

	/**
	 * Validate on lost-password submission.
	 *
	 * @param WP_Error $errors
	 */
	public function lostpassword_post( $errors ) {
		$settings = oopspam_ls_get_settings();
		if ( empty( $settings['enabled'] ) || empty( $settings['protect_lostpassword'] ) ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$token = isset( $_POST['oopspam_ls_token'] )
			? sanitize_text_field( wp_unslash( $_POST['oopspam_ls_token'] ) )
			: '';
		// phpcs:enable

		$check = OOPSpam_LS_Token::validate( $token );
		if ( is_wp_error( $check ) ) {
			$errors->add(
				'oopspam_ls_unverified',
				'<strong>' . esc_html__( 'Error:', 'oopspam-login-shield' ) . '</strong> ' . esc_html( $check->get_error_message() )
			);
		}
	}
}
