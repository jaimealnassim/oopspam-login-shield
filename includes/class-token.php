<?php
/**
 * Signed verification token used to bridge the AJAX check and the
 * authentication / registration / lost-password validation hooks.
 *
 * Tokens are:
 *   - HMAC-SHA256 signed with a per-site secret
 *   - Time-limited (default 10 minutes)
 *   - Bound to a hash of the requesting IP at issuance
 *   - Single-use (tracked via a transient nonce)
 *
 * @package OOPSpam_Login_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOPSpam_LS_Token {

	/**
	 * Issue a fresh token.
	 *
	 * @param array $payload Optional metadata to embed (e.g. skip flags).
	 * @return string Token in the form "base64body.signature".
	 */
	public static function issue( $payload = array() ) {
		$nonce = wp_generate_password( 16, false );

		$data = array(
			'iat' => time(),
			'iph' => self::ip_hash(),
			'n'   => $nonce,
			'p'   => is_array( $payload ) ? $payload : array(),
		);

		$body  = self::b64url_encode( wp_json_encode( $data ) );
		$sig   = hash_hmac( 'sha256', $body, self::get_secret() );
		$token = $body . '.' . $sig;

		// Mark the nonce as available for one consumption.
		set_transient( self::nonce_key( $nonce ), 1, OOPSPAM_LS_TOKEN_TTL );

		return $token;
	}

	/**
	 * Per-request cache of validation results, keyed by raw token string.
	 *
	 * WordPress auth flow can fire the `authenticate` filter multiple times
	 * per login (once from wp_signon, again indirectly from wp_authenticate
	 * during nonce/cookie processing, and other plugins may re-invoke it).
	 * Our token validator consumes the token's single-use nonce on first
	 * call, which means the second call would return a "token already used"
	 * error, blocking valid logins.
	 *
	 * Caching by token string lets us return the same result for repeat
	 * validations of the same token within one request, while still
	 * preserving single-use semantics across separate requests (cache is
	 * static and dies with the request).
	 *
	 * @var array<string, array|WP_Error>
	 */
	private static array $request_cache = array();

	/**
	 * Validate a token. Returns the decoded payload array on success,
	 * or a WP_Error describing why it was rejected.
	 *
	 * Idempotent within a single request — repeat validation of the same
	 * token returns the cached result, so the auth chain firing multiple
	 * times in one login attempt does not falsely trip the single-use guard.
	 *
	 * @param string $token Raw token string from the request.
	 * @return array|WP_Error
	 */
	public static function validate( $token ) {
		// Repeat validation of an already-seen token in this request returns
		// the cached result. This is critical because WordPress's auth flow
		// can run the `authenticate` filter chain more than once per login
		// (wp_signon, wp_authenticate, plus any plugin that re-fires it).
		if ( is_string( $token ) && isset( self::$request_cache[ $token ] ) ) {
			return self::$request_cache[ $token ];
		}

		$result = self::do_validate( $token );

		if ( is_string( $token ) && '' !== $token ) {
			self::$request_cache[ $token ] = $result;
		}

		return $result;
	}

	/**
	 * Inner validation routine. Called once per token per request via the
	 * cache wrapper above.
	 *
	 * @param string $token
	 * @return array|WP_Error
	 */
	private static function do_validate( $token ) {
		if ( ! is_string( $token ) || '' === $token || strpos( $token, '.' ) === false ) {
			return new WP_Error(
				'oopspam_ls_invalid',
				__( 'Verification token missing. Please refresh the page and try again.', 'oopspam-login-shield' )
			);
		}

		$parts = explode( '.', $token, 2 );
		if ( count( $parts ) !== 2 ) {
			return new WP_Error(
				'oopspam_ls_malformed',
				__( 'Verification token is malformed.', 'oopspam-login-shield' )
			);
		}

		list( $body, $sig ) = $parts;

		$expected = hash_hmac( 'sha256', $body, self::get_secret() );
		if ( ! hash_equals( $expected, $sig ) ) {
			return new WP_Error(
				'oopspam_ls_signature',
				__( 'Verification token signature mismatch.', 'oopspam-login-shield' )
			);
		}

		$json = self::b64url_decode( $body );
		if ( false === $json ) {
			return new WP_Error( 'oopspam_ls_decode', __( 'Verification token could not be decoded.', 'oopspam-login-shield' ) );
		}

		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || empty( $data['iat'] ) || empty( $data['n'] ) || empty( $data['iph'] ) ) {
			return new WP_Error( 'oopspam_ls_payload', __( 'Verification token payload is invalid.', 'oopspam-login-shield' ) );
		}

		// Time check.
		if ( ( time() - (int) $data['iat'] ) > OOPSPAM_LS_TOKEN_TTL ) {
			return new WP_Error( 'oopspam_ls_expired', __( 'Verification expired. Please refresh and try again.', 'oopspam-login-shield' ) );
		}

		// IP binding check (allows admins to override via filter for proxy-heavy setups).
		$enforce_ip = (bool) apply_filters( 'oopspam_ls_enforce_ip_binding', true );
		if ( $enforce_ip && ! hash_equals( $data['iph'], self::ip_hash() ) ) {
			return new WP_Error( 'oopspam_ls_ip', __( 'Verification was issued for a different network. Please refresh.', 'oopspam-login-shield' ) );
		}

		// Single-use check, atomic check-and-consume.
		// delete_transient() returns true only if the nonce was present and was
		// actually deleted by THIS call. If a parallel request just consumed it,
		// we'll get false and reject. This avoids the get_transient + delete_transient
		// race window where two parallel submits could both pass.
		//
		// Within a single request, the static cache above prevents re-entry,
		// so this only fires once per token even if the auth chain runs many times.
		$nonce_key = self::nonce_key( $data['n'] );
		if ( ! delete_transient( $nonce_key ) ) {
			return new WP_Error( 'oopspam_ls_replay', __( 'Verification token already used. Please refresh.', 'oopspam-login-shield' ) );
		}

		return $data;
	}

	/**
	 * Per-site signing secret. Generated lazily if missing.
	 *
	 * @return string
	 */
	private static function get_secret() {
		$secret = get_option( 'oopspam_ls_secret' );
		if ( empty( $secret ) ) {
			$secret = wp_generate_password( 64, true, true );
			update_option( 'oopspam_ls_secret', $secret, false );
		}
		return $secret;
	}

	/**
	 * Hashed real client IP, salted with auth salt.
	 *
	 * IMPORTANT: intentionally independent of the OOPSpam parent plugin's
	 * `oopspamantispam_get_ip()` helper. That helper may return an empty string
	 * when the OOPSpam "don't capture IP" privacy setting is enabled — which is
	 * correct for what gets SENT to the OOPSpam API, but would collapse our LOCAL
	 * token binding into a single shared hash for all visitors.
	 *
	 * We resolve the real client IP ourselves in priority order:
	 *   1. CF-Connecting-IP  — Cloudflare's canonical real-client header.
	 *   2. True-Client-IP    — Akamai / Cloudflare Enterprise.
	 *   3. X-Real-IP         — nginx / many proxies.
	 *   4. X-Forwarded-For   — leftmost (originating) hop; may be a list.
	 *   5. REMOTE_ADDR       — last resort (direct connection or same-node CDN).
	 *
	 * Why this matters: when a CDN or load balancer is in front of WordPress,
	 * REMOTE_ADDR is the edge-node IP. The AJAX verify request and the login
	 * form POST may hit DIFFERENT edge nodes, producing different REMOTE_ADDR
	 * values and causing the IP hash to mismatch — the exact bug that produced
	 * "Verification was issued for a different network."
	 *
	 * We only hash the IP; we never store, log, or transmit it.
	 *
	 * @return string
	 */
	private static function ip_hash() {
		$ip = self::resolve_client_ip();
		// Stable hash even in non-HTTP contexts (CLI tests, fallthroughs).
		return hash( 'sha256', ( '' === $ip ? 'no-remote-addr' : $ip ) . '|' . wp_salt( 'auth' ) );
	}

	/**
	 * Resolve the real client IP from proxy / CDN headers, falling back to
	 * REMOTE_ADDR. Returns an empty string only in non-HTTP contexts.
	 *
	 * @return string Validated IPv4 or IPv6 address, or empty string.
	 */
	private static function resolve_client_ip() {
		// 1. Cloudflare: CF-Connecting-IP is always the real client.
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		// 2. True-Client-IP (Akamai / Cloudflare Enterprise).
		if ( ! empty( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		// 3. X-Real-IP (nginx, many load balancers).
		if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		// 4. X-Forwarded-For — may be a comma-separated list; take leftmost valid IP.
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$forwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			foreach ( array_map( 'trim', explode( ',', $forwarded ) ) as $candidate ) {
				if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					return $candidate;
				}
			}
		}

		// 5. Direct connection — REMOTE_ADDR is the only option left.
		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		return '';
	}

	/**
	 * Transient key for a token's single-use nonce.
	 *
	 * @param string $nonce
	 * @return string
	 */
	private static function nonce_key( $nonce ) {
		return 'oopspam_ls_t_' . preg_replace( '/[^A-Za-z0-9]/', '', $nonce );
	}

	/**
	 * URL-safe base64 encode.
	 *
	 * @param string $data
	 * @return string
	 */
	private static function b64url_encode( $data ) {
		return rtrim( strtr( base64_encode( (string) $data ), '+/', '-_' ), '=' );
	}

	/**
	 * URL-safe base64 decode. Returns false on failure.
	 *
	 * @param string $data
	 * @return string|false
	 */
	private static function b64url_decode( $data ) {
		$pad = strlen( $data ) % 4;
		if ( $pad ) {
			$data .= str_repeat( '=', 4 - $pad );
		}
		return base64_decode( strtr( $data, '-_', '+/' ), true );
	}
}
