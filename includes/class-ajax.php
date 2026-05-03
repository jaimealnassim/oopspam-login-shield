<?php
/**
 * AJAX endpoint that the widget hits to perform the OOPSpam check
 * and receive a signed token.
 *
 * @package OOPSpam_Login_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOPSpam_LS_Ajax {

	const ACTION = 'oopspam_ls_verify';
	const NONCE  = 'oopspam_ls_verify';

	public function __construct() {
		add_action( 'wp_ajax_' . self::ACTION,        $this->verify( ... ) );
		add_action( 'wp_ajax_nopriv_' . self::ACTION, $this->verify( ... ) );
	}

	/**
	 * Handle the AJAX verification request.
	 *
	 * Strategy:
	 *   - Confirm CSRF nonce.
	 *   - If shield disabled → issue a permissive token (so legit users aren't blocked).
	 *   - If OOPSpam isn't installed/configured → issue a permissive token (fail open).
	 *   - Otherwise call OOPSpam with IP only (we don't have the username yet).
	 *     Spam → reject. Ham (or API error / rate-limit) → issue token.
	 */
	public function verify() {
		// Nonce check. Returns 403 to user automatically on failure.
		check_ajax_referer( self::NONCE, 'nonce' );

		$settings = oopspam_ls_get_settings();

		// Plugin disabled — still issue a token so the widget shows "verified" for normal UX.
		if ( empty( $settings['enabled'] ) ) {
			wp_send_json_success( array(
				'token'   => OOPSpam_LS_Token::issue( array( 'mode' => 'disabled' ) ),
				'checked' => false,
			) );
		}

		// Parent plugin missing or unconfigured — fail open.
		if ( ! oopspam_ls_is_oopspam_ready() ) {
			wp_send_json_success( array(
				'token'   => OOPSpam_LS_Token::issue( array( 'mode' => 'unconfigured' ) ),
				'checked' => false,
			) );
		}

		$ip = oopspam_ls_get_ip();

		// Sentinel content > 20 chars so the parent's optional length filter
		// doesn't auto-flag this as spam. Doubles as a useful description if
		// it ever ends up in the admin entries table.
		$content = 'OOPSpam Login Shield: page-load preflight check (no user content yet).';

		// log: false — every login page load would otherwise create a ham
		// entry in OOPSpam's table, drowning out actually-interesting ones.
		$result = oopspam_ls_run_check(
			$ip,
			'',
			$content,
			array(
				'log'     => false,
				'form_id' => 'oopspam-login-shield-preflight',
			)
		);

		// Helper returned null — parent plugin missing/short-circuited.
		if ( null === $result ) {
			// Fail open — don't lock out users due to API hiccups.
			wp_send_json_success( array(
				'token'   => OOPSpam_LS_Token::issue( array( 'mode' => 'api_unavailable' ) ),
				'checked' => false,
			) );
		}

		// Negative scores in OOPSpam = various API errors / rate limit. Fail open.
		if ( $result['Score'] < 0 ) {
			wp_send_json_success( array(
				'token'   => OOPSpam_LS_Token::issue( array( 'mode' => 'api_degraded', 'score' => $result['Score'] ) ),
				'checked' => false,
			) );
		}

		if ( $result['isSpam'] ) {
			// Spam — DON'T issue a token.
			$msg = ! empty( $settings['spam_message'] )
				? $settings['spam_message']
				: __( 'Your request was blocked.', 'oopspam-login-shield' );

			$reason = sanitize_text_field( $result['Reason'] );

			/**
			 * Fires when a pre-flight verification is rejected as spam.
			 *
			 * @param array  $result   Normalised OOPSpam result array.
			 * @param string $ip       Detected sender IP.
			 */
			do_action( 'oopspam_ls_blocked_preflight', $result, $ip );

			wp_send_json_error(
				array(
					'message' => $msg,
					'reason'  => $reason,
				)
			);
		}

		// Ham — issue token.
		wp_send_json_success( array(
			'token'   => OOPSpam_LS_Token::issue( array( 'mode' => 'ham' ) ),
			'checked' => true,
		) );
	}
}
