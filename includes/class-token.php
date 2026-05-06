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

		// Use the same binding mode at issue time as we'll use at validate
		// time. When mode is 'off', we still embed a stable placeholder so
		// the payload schema doesn't change; the validator skips the check
		// entirely in that mode, so the value is never compared.
		$mode = self::resolve_binding_mode();
		$iph  = ( 'off' === $mode )
			? hash( 'sha256', 'binding-off|' . wp_salt( 'auth' ) )
			: self::ip_hash( $mode );

		$data = array(
			'iat' => time(),
			'iph' => $iph,
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

		// IP binding check, mode-aware.
		//
		//   off:    skip the check entirely. Token is still HMAC-signed, single-use,
		//           and time-bound, which is sufficient for almost every site.
		//   subnet: bind to the visitor's network neighborhood (IPv4 /24, IPv6 /64).
		//           Allows IP-shift within a single ISP/CDN region.
		//   strict: bind to the exact IP. Most secure but most likely to false-
		//           positive when visitors are behind multi-edge CDNs.
		//
		// The legacy oopspam_ls_enforce_ip_binding filter still works as a
		// boolean override for backward compatibility: returning false forces
		// 'off' mode regardless of the setting.
		$mode = self::resolve_binding_mode();
		if ( 'off' !== $mode && ! hash_equals( $data['iph'], self::ip_hash( $mode ) ) ) {
			return new WP_Error(
				'oopspam_ls_ip',
				__( 'Verification was issued for a different network. Please refresh.', 'oopspam-login-shield' )
			);
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
	 * Resolve the IP binding mode currently in effect.
	 *
	 * Reads the `ip_binding_mode` setting (off | subnet | strict, default off)
	 * and applies the legacy `oopspam_ls_enforce_ip_binding` filter for
	 * backward compatibility (returning false from that filter forces 'off'
	 * regardless of the setting).
	 *
	 * @return string One of 'off', 'subnet', 'strict'.
	 */
	private static function resolve_binding_mode(): string {
		$settings = function_exists( 'oopspam_ls_get_settings' ) ? oopspam_ls_get_settings() : array();
		$mode     = isset( $settings['ip_binding_mode'] ) ? (string) $settings['ip_binding_mode'] : 'off';
		if ( ! in_array( $mode, array( 'off', 'subnet', 'strict' ), true ) ) {
			$mode = 'off';
		}

		// Legacy filter: returning false short-circuits to 'off'.
		if ( false === apply_filters( 'oopspam_ls_enforce_ip_binding', true ) ) {
			$mode = 'off';
		}

		return $mode;
	}

	/**
	 * Hashed remote IP, salted with auth salt.
	 *
	 * IMPORTANT: this uses REMOTE_ADDR directly and is intentionally
	 * independent of OOPSpam's `oopspamantispam_get_ip()` helper. That helper
	 * returns an empty string when OOPSpam's "don't capture IP" privacy
	 * setting is on (correct for what gets sent to the OOPSpam API, wrong
	 * for our local token binding which would collapse to a single shared
	 * hash for all visitors). We only ever hash the IP; we never store,
	 * log, or transmit it.
	 *
	 * Modes:
	 *   - strict: hash the full IP
	 *   - subnet: hash the network portion (IPv4 /24, IPv6 /64). This trades
	 *     some specificity for resilience against multi-edge CDN routing.
	 *
	 * @param string $mode Binding mode ('strict' or 'subnet'). 'off' should
	 *                     not reach here; the caller checks before calling.
	 * @return string
	 */
	private static function ip_hash( string $mode = 'strict' ): string {
		$ip = ! empty( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';

		if ( '' === $ip ) {
			return hash( 'sha256', 'no-remote-addr|' . wp_salt( 'auth' ) );
		}

		if ( 'subnet' === $mode ) {
			$ip = self::ip_to_subnet( $ip );
		}

		return hash( 'sha256', $ip . '|' . wp_salt( 'auth' ) );
	}

	/**
	 * Reduce an IP address to its network subnet.
	 *
	 * IPv4: drop the last octet (/24). 192.0.2.42 -> 192.0.2.0
	 * IPv6: keep first 4 hex groups (/64). 2001:db8::1 -> 2001:db8:0:0
	 *
	 * Falls back to the input unchanged on parse failure (so we still get a
	 * stable hash, just less coarse than intended).
	 *
	 * @param string $ip
	 * @return string Subnet representation of the IP.
	 */
	private static function ip_to_subnet( string $ip ): string {
		// IPv4: a.b.c.d -> a.b.c.0
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			if ( 4 === count( $parts ) ) {
				return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0';
			}
			return $ip;
		}

		// IPv6: keep first 64 bits (4 groups of 16 bits). inet_pton + truncate
		// is the canonical way; falls back to text manipulation if pton fails.
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = @inet_pton( $ip );
			if ( false !== $packed && 16 === strlen( $packed ) ) {
				// Keep first 8 bytes (64 bits), zero the rest.
				$truncated = substr( $packed, 0, 8 ) . str_repeat( "\0", 8 );
				$readable  = inet_ntop( $truncated );
				if ( false !== $readable ) {
					return $readable;
				}
			}
			return $ip;
		}

		return $ip;
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
