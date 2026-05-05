/**
 * OOPSpam Login Shield — widget script
 *
 * - Auto-verifies on page load (Altcha-style) when configured.
 * - On manual mode, verifies on click/keyboard activation.
 * - Prevents form submission while verification is pending or failed,
 *   and re-attempts verification when the user submits with no token.
 */
(function () {
	'use strict';

	if (typeof window.OOPSpamLS === 'undefined') {
		return;
	}
	var CFG = window.OOPSpamLS;

	function init() {
		var widget = document.getElementById('oopspam-ls-widget');
		if (!widget || widget.dataset.initialized === '1') return;
		widget.dataset.initialized = '1';

		var input    = document.getElementById('oopspam-ls-token');
		var checkbox = widget.querySelector('.oolsh-checkbox');
		var label    = widget.querySelector('.oolsh-label');
		var form     = widget.closest('form');
		var inFlight = false;

		function setState(state, text) {
			widget.setAttribute('data-state', state);
			if (checkbox) {
				checkbox.setAttribute('aria-checked', state === 'verified' ? 'true' : 'false');
			}
			if (text && label) {
				label.textContent = text;
			}
		}

		function verify(onComplete) {
			if (inFlight) return;
			if (widget.dataset.state === 'verified') {
				if (typeof onComplete === 'function') onComplete(true);
				return;
			}
			inFlight = true;
			setState('verifying', CFG.i18n.verifying);

			var body = new URLSearchParams();
			body.append('action', 'oopspam_ls_verify');
			body.append('nonce', CFG.nonce);

			fetch(CFG.ajaxUrl, {
				method: 'POST',
				body: body.toString(),
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' }
			})
			.then(function (res) {
				return res.json().catch(function () { return null; }).then(function (data) {
					return { status: res.status, data: data };
				});
			})
			.then(function (out) {
				inFlight = false;
				var data = out && out.data;
				if (data && data.success && data.data && data.data.token) {
					if (input) input.value = data.data.token;
					setState('verified', CFG.i18n.verified);
					if (typeof onComplete === 'function') onComplete(true);
				} else {
					var msg = (data && data.data && data.data.message) ? data.data.message : CFG.i18n.failed;
					setState('failed', msg);
					if (input) input.value = '';
					if (typeof onComplete === 'function') onComplete(false);
				}
			})
			.catch(function () {
				inFlight = false;
				setState('failed', CFG.i18n.failed);
				if (input) input.value = '';
				if (typeof onComplete === 'function') onComplete(false);
			});
		}

		// Click / keyboard activation
		function activate(e) {
			var s = widget.dataset.state;
			if (s === 'idle' || s === 'failed') {
				if (e) {
					e.preventDefault();
				}
				verify();
			}
		}
		if (checkbox) {
			checkbox.addEventListener('click', activate);
			checkbox.addEventListener('keydown', function (e) {
				if (e.key === ' ' || e.key === 'Enter' || e.keyCode === 32 || e.keyCode === 13) {
					e.preventDefault();
					activate(e);
				}
			});
		}

		// Submit gating.
		//
		// In MANUAL mode (autoVerify off), we never auto-trigger verification
		// on submit. The user must click the checkbox first. If they try to
		// submit unverified, we block submission, focus the checkbox, shake
		// the widget for visual feedback, and update the label.
		//
		// In AUTO mode (autoVerify on), the widget already verifies on page
		// load, so by the time the user submits, the state should be 'verified'.
		// If verification is still in flight or failed, we hold the submit
		// and resolve before resubmitting via the submit button (not
		// form.submit()), so other plugins' submit handlers still fire.
		//
		// A `pending` guard prevents rapid double-clicks from scheduling
		// two resubmits.
		if (form) {
			var submitBtn = form.querySelector('input[type="submit"], button[type="submit"]:not([formnovalidate])')
				|| form.querySelector('button[type="submit"]');
			var pending = false;

			form.addEventListener('submit', function (e) {
				var s = widget.dataset.state;
				if (s === 'verified') {
					return; // good to go — let every other handler run too
				}
				e.preventDefault();

				// MANUAL mode: never auto-verify on submit. Force the user
				// to click the checkbox.
				if (!CFG.autoVerify) {
					var msg = (s === 'verifying')
						? (CFG.i18n.wait || CFG.i18n.verifying)
						: (CFG.i18n.clickToVerify || "Please click the checkbox above to verify you're not a robot.");
					if (label) label.textContent = msg;
					// Visual cue: shake animation, focus the checkbox.
					widget.classList.remove('oolsh-shake');
					// Force reflow so the animation can replay.
					void widget.offsetWidth;
					widget.classList.add('oolsh-shake');
					setTimeout(function () {
						widget.classList.remove('oolsh-shake');
					}, 700);
					if (checkbox && typeof checkbox.focus === 'function') {
						try { checkbox.focus(); } catch (err) {}
					}
					return;
				}

				// AUTO mode: hold the submit and resolve verification first.
				if (pending) return;
				pending = true;

				var finish = function (ok) {
					pending = false;
					if (!ok) return;
					if (submitBtn) {
						submitBtn.click();
					} else {
						HTMLFormElement.prototype.submit.call(form);
					}
				};

				if (s === 'verifying') {
					waitForReady(finish);
				} else {
					verify(finish);
				}
			});
		}

		function waitForReady(cb) {
			var tries = 0;
			(function poll() {
				if (widget.dataset.state === 'verified') {
					return cb(true);
				}
				if (widget.dataset.state === 'failed') {
					return cb(false);
				}
				if (++tries > 80) { // ~8 seconds
					return cb(false);
				}
				setTimeout(poll, 100);
			})();
		}

		// Initial state
		if (CFG.autoVerify) {
			// Slight delay so the spinner is visible to the user.
			setTimeout(function () { verify(); }, 60);
		} else {
			setState('idle', CFG.i18n.idle);
		}
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
