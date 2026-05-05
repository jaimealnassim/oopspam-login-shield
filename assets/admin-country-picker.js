/**
 * OOPSpam Login Shield: country picker for the Connector-specific rules.
 *
 * Progressive enhancement around the existing textarea. The textarea is
 * still the source of truth (it's what gets posted to the server). This
 * script adds:
 *
 *   - A grid of clickable country chips (one per ISO country code).
 *   - Region quick-action buttons that add or remove whole groups
 *     (China & Russia, Africa, Europe, North America, etc.).
 *   - Live sync: edit the textarea -> chips update; click chips -> textarea updates.
 *
 * If JS is disabled, the textarea still works exactly as before.
 */
(function () {
	'use strict';

	if (typeof document === 'undefined') return;

	// ISO 3166-1 alpha-2 codes by region. Curated to match how site admins
	// actually think about geographic blocking, not strict UN regions.
	// "MENA" overlaps with Africa and Asia by design; that's the point.
	var REGIONS = {
		'priority':       ['CN', 'RU'],
		'africa':         ['DZ','AO','BJ','BW','BF','BI','CM','CV','CF','TD','KM','CG','CD','CI','DJ','EG','GQ','ER','SZ','ET','GA','GM','GH','GN','GW','KE','LS','LR','LY','MG','MW','ML','MR','MU','MA','MZ','NA','NE','NG','RW','ST','SN','SC','SL','SO','ZA','SS','SD','TZ','TG','TN','UG','EH','ZM','ZW'],
		'europe':         ['AL','AD','AM','AT','AZ','BY','BE','BA','BG','HR','CY','CZ','DK','EE','FI','FR','GE','DE','GR','HU','IS','IE','IT','XK','LV','LI','LT','LU','MT','MD','MC','ME','NL','MK','NO','PL','PT','RO','SM','RS','SK','SI','ES','SE','CH','TR','UA','GB','VA'],
		'northAmerica':   ['CA','MX','US','GT','BZ','SV','HN','NI','CR','PA','CU','DO','HT','JM','BS','BB','TT','AG','DM','GD','KN','LC','VC'],
		'southAmerica':   ['AR','BO','BR','CL','CO','EC','GY','PY','PE','SR','UY','VE'],
		'mena':           ['DZ','BH','EG','IR','IQ','IL','JO','KW','LB','LY','MA','OM','PS','QA','SA','SY','TN','AE','YE'],
		'asia':           ['AF','BD','BT','BN','KH','CN','HK','IN','ID','JP','KZ','KG','LA','MO','MY','MV','MN','MM','NP','KP','PK','PH','SG','KR','LK','TW','TJ','TH','TL','TM','UZ','VN'],
		'oceania':        ['AU','FJ','KI','MH','FM','NR','NZ','PW','PG','WS','SB','TO','TV','VU']
	};

	// Curated chip list — countries we display as toggleable chips. Limit
	// scope: showing all 240+ ISO codes is overwhelming. This covers the
	// regions in REGIONS so every region button has something to act on.
	// Sourced from the union of REGIONS (computed below) so the two stay
	// in sync.
	var ALL_COUNTRIES = (function () {
		var seen = {};
		var out = [];
		Object.keys(REGIONS).forEach(function (key) {
			REGIONS[key].forEach(function (cc) {
				if (!seen[cc]) {
					seen[cc] = true;
					out.push(cc);
				}
			});
		});
		out.sort();
		return out;
	})();

	// Human-readable country name lookup for chip labels and tooltips.
	// Stored separately from REGIONS so the region arrays are compact.
	var NAMES = {
		AD:'Andorra', AE:'UAE', AF:'Afghanistan', AG:'Antigua & Barbuda', AL:'Albania', AM:'Armenia', AO:'Angola', AR:'Argentina', AT:'Austria', AU:'Australia', AZ:'Azerbaijan',
		BA:'Bosnia & Herz.', BB:'Barbados', BD:'Bangladesh', BE:'Belgium', BF:'Burkina Faso', BG:'Bulgaria', BH:'Bahrain', BI:'Burundi', BJ:'Benin', BN:'Brunei', BO:'Bolivia', BR:'Brazil', BS:'Bahamas', BT:'Bhutan', BW:'Botswana', BY:'Belarus', BZ:'Belize',
		CA:'Canada', CD:'DR Congo', CF:'CAR', CG:'Congo', CH:'Switzerland', CI:"Côte d'Ivoire", CL:'Chile', CM:'Cameroon', CN:'China', CO:'Colombia', CR:'Costa Rica', CU:'Cuba', CV:'Cabo Verde', CY:'Cyprus', CZ:'Czechia',
		DE:'Germany', DJ:'Djibouti', DK:'Denmark', DM:'Dominica', DO:'Dominican Rep.', DZ:'Algeria',
		EC:'Ecuador', EE:'Estonia', EG:'Egypt', EH:'W. Sahara', ER:'Eritrea', ES:'Spain', ET:'Ethiopia',
		FI:'Finland', FJ:'Fiji', FM:'Micronesia', FR:'France',
		GA:'Gabon', GB:'UK', GD:'Grenada', GE:'Georgia', GH:'Ghana', GM:'Gambia', GN:'Guinea', GQ:'Eq. Guinea', GR:'Greece', GT:'Guatemala', GW:'Guinea-Bissau', GY:'Guyana',
		HK:'Hong Kong', HN:'Honduras', HR:'Croatia', HT:'Haiti', HU:'Hungary',
		ID:'Indonesia', IE:'Ireland', IL:'Israel', IN:'India', IQ:'Iraq', IR:'Iran', IS:'Iceland', IT:'Italy',
		JM:'Jamaica', JO:'Jordan', JP:'Japan',
		KE:'Kenya', KG:'Kyrgyzstan', KH:'Cambodia', KI:'Kiribati', KM:'Comoros', KN:'St. Kitts & Nevis', KP:'North Korea', KR:'South Korea', KW:'Kuwait', KZ:'Kazakhstan',
		LA:'Laos', LB:'Lebanon', LC:'St. Lucia', LI:'Liechtenstein', LK:'Sri Lanka', LR:'Liberia', LS:'Lesotho', LT:'Lithuania', LU:'Luxembourg', LV:'Latvia', LY:'Libya',
		MA:'Morocco', MC:'Monaco', MD:'Moldova', ME:'Montenegro', MG:'Madagascar', MH:'Marshall Is.', MK:'N. Macedonia', ML:'Mali', MM:'Myanmar', MN:'Mongolia', MO:'Macau', MR:'Mauritania', MT:'Malta', MU:'Mauritius', MV:'Maldives', MW:'Malawi', MX:'Mexico', MY:'Malaysia', MZ:'Mozambique',
		NA:'Namibia', NE:'Niger', NG:'Nigeria', NI:'Nicaragua', NL:'Netherlands', NO:'Norway', NP:'Nepal', NR:'Nauru', NZ:'New Zealand',
		OM:'Oman',
		PA:'Panama', PE:'Peru', PG:'Papua N.G.', PH:'Philippines', PK:'Pakistan', PL:'Poland', PS:'Palestine', PT:'Portugal', PW:'Palau', PY:'Paraguay',
		QA:'Qatar',
		RO:'Romania', RS:'Serbia', RU:'Russia', RW:'Rwanda',
		SA:'Saudi Arabia', SB:'Solomon Is.', SC:'Seychelles', SD:'Sudan', SE:'Sweden', SG:'Singapore', SI:'Slovenia', SK:'Slovakia', SL:'Sierra Leone', SM:'San Marino', SN:'Senegal', SO:'Somalia', SR:'Suriname', SS:'S. Sudan', ST:'São Tomé', SV:'El Salvador', SY:'Syria', SZ:'Eswatini',
		TD:'Chad', TG:'Togo', TH:'Thailand', TJ:'Tajikistan', TL:'Timor-Leste', TM:'Turkmenistan', TN:'Tunisia', TO:'Tonga', TR:'Türkiye', TT:'Trinidad & Tobago', TV:'Tuvalu', TW:'Taiwan', TZ:'Tanzania',
		UA:'Ukraine', UG:'Uganda', US:'USA', UY:'Uruguay', UZ:'Uzbekistan',
		VA:'Vatican', VC:'St. Vincent & Gren.', VE:'Venezuela', VN:'Vietnam', VU:'Vanuatu',
		WS:'Samoa',
		XK:'Kosovo',
		YE:'Yemen',
		ZA:'South Africa', ZM:'Zambia', ZW:'Zimbabwe'
	};

	function parseTextarea(value) {
		if (!value) return [];
		var out = {};
		var parts = value.split(/[\s,]+/);
		for (var i = 0; i < parts.length; i++) {
			var c = (parts[i] || '').trim().toUpperCase();
			if (c.length === 2 && /^[A-Z]+$/.test(c)) {
				out[c] = true;
			}
		}
		return Object.keys(out).sort();
	}

	function init() {
		var textarea = document.getElementById('oopspam_ls_connector_blocked_countries');
		if (!textarea) return;
		// Idempotency: if we already enhanced this textarea, bail.
		if (textarea.dataset.pickerBound === '1') return;
		textarea.dataset.pickerBound = '1';

		// The picker is only useful in "custom" mode. Hide it when "inherit"
		// (Use OOPSpam plugin setting) is selected, and show/hide it as the
		// admin toggles the radio.
		var modeRadios = document.querySelectorAll('input[name="oopspam_ls_settings[connector_country_mode]"]');

		// Build the picker UI above the textarea.
		var wrapper = document.createElement('div');
		wrapper.className = 'oopspam-ls-country-picker';

		// Region buttons row.
		var regionsRow = document.createElement('div');
		regionsRow.className = 'oopspam-ls-region-row';

		// One toggle button per region. Click adds all countries in the
		// region; if all are already selected, click removes them. The label
		// flips between "+ X" and "− X" based on current selection state.
		// "Clear all" stays separate because it always clears, not toggles.
		var REGION_BUTTONS = [
			{ key: 'priority',     label: 'China & Russia' },
			{ key: 'africa',       label: 'Africa' },
			{ key: 'europe',       label: 'Europe' },
			{ key: 'northAmerica', label: 'North America' },
			{ key: 'southAmerica', label: 'South America' },
			{ key: 'mena',         label: 'MENA' },
			{ key: 'asia',         label: 'Asia' },
			{ key: 'oceania',      label: 'Oceania' }
		];

		var regionBtnElements = []; // tracked so refreshUI can update their labels

		REGION_BUTTONS.forEach(function (cfg) {
			var btn = document.createElement('button');
			btn.type = 'button';
			btn.className = 'button button-small oopspam-ls-region-btn';
			btn.dataset.regionKey = cfg.key;
			btn.dataset.regionLabel = cfg.label;
			btn.textContent = '+ ' + cfg.label;
			btn.addEventListener('click', function () {
				var codes = REGIONS[cfg.key] || [];
				if (codes.length === 0) return;
				var current = parseTextarea(textarea.value);
				var asMap = {};
				current.forEach(function (c) { asMap[c] = true; });
				// Toggle: if all in region are already selected, remove them all;
				// otherwise add all (which is a no-op for the ones already present).
				var allSelected = codes.every(function (c) { return asMap[c]; });
				if (allSelected) {
					codes.forEach(function (c) { delete asMap[c]; });
				} else {
					codes.forEach(function (c) { asMap[c] = true; });
				}
				setSelected(asMap);
			});
			regionsRow.appendChild(btn);
			regionBtnElements.push(btn);
		});

		// "Clear all" button — always clears, never toggles.
		var clearBtn = document.createElement('button');
		clearBtn.type = 'button';
		clearBtn.className = 'button button-small oopspam-ls-region-btn is-remove';
		clearBtn.textContent = 'Clear all';
		clearBtn.addEventListener('click', function () { setSelected({}); });
		regionsRow.appendChild(clearBtn);

		wrapper.appendChild(regionsRow);

		// Status line.
		var status = document.createElement('div');
		status.className = 'oopspam-ls-picker-status';
		wrapper.appendChild(status);

		// Chip grid.
		var grid = document.createElement('div');
		grid.className = 'oopspam-ls-country-grid';
		var chipMap = {}; // code -> chip element

		ALL_COUNTRIES.forEach(function (code) {
			var chip = document.createElement('button');
			chip.type = 'button';
			chip.className = 'oopspam-ls-chip';
			chip.dataset.code = code;
			chip.title = (NAMES[code] || code) + ' (' + code + ')';
			var name = NAMES[code] || code;
			// Non-breaking space between code and name as a guaranteed visual
			// separator that doesn't depend on flex `gap` or margin CSS rules
			// loading correctly. The CSS rules add nicer spacing on top.
			chip.innerHTML = '<span class="oopspam-ls-chip-code">' + code + '</span>' +
				'&nbsp;' +
				'<span class="oopspam-ls-chip-name">' + name + '</span>';
			chip.addEventListener('click', function () {
				var current = parseTextarea(textarea.value);
				var asMap = {};
				current.forEach(function (c) { asMap[c] = true; });
				if (asMap[code]) {
					delete asMap[code];
				} else {
					asMap[code] = true;
				}
				setSelected(asMap);
			});
			chipMap[code] = chip;
			grid.appendChild(chip);
		});
		wrapper.appendChild(grid);

		// Insert wrapper before the textarea.
		textarea.parentNode.insertBefore(wrapper, textarea);

		// Mode toggle: hide picker (and textarea) when in inherit mode. Uses
		// a class with `display:none !important` rather than inline style so
		// nothing else can accidentally un-hide it. Also applies inline style
		// as a belt-and-suspenders fallback in case the class CSS hasn't
		// loaded yet.
		function applyModeVisibility() {
			var selected = 'inherit';
			modeRadios.forEach(function (r) {
				if (r.checked) selected = r.value;
			});
			var customMode = (selected === 'custom');
			if (customMode) {
				wrapper.classList.remove('oopspam-ls-picker-hidden');
				textarea.classList.remove('oopspam-ls-picker-hidden');
				wrapper.style.display = '';
				textarea.style.display = '';
			} else {
				wrapper.classList.add('oopspam-ls-picker-hidden');
				textarea.classList.add('oopspam-ls-picker-hidden');
				wrapper.style.display = 'none';
				textarea.style.display = 'none';
			}
		}
		modeRadios.forEach(function (r) {
			r.addEventListener('change', applyModeVisibility);
		});
		applyModeVisibility();

		function setSelected(asMap) {
			var codes = Object.keys(asMap).sort();
			textarea.value = codes.join(', ');
			refreshUI();
			// Notify any other listeners on the textarea.
			textarea.dispatchEvent(new Event('input', { bubbles: true }));
		}

		function refreshUI() {
			var codes = parseTextarea(textarea.value);
			var asMap = {};
			codes.forEach(function (c) { asMap[c] = true; });

			// Update chip pressed state.
			Object.keys(chipMap).forEach(function (code) {
				var chip = chipMap[code];
				if (asMap[code]) {
					chip.classList.add('is-selected');
					chip.setAttribute('aria-pressed', 'true');
				} else {
					chip.classList.remove('is-selected');
					chip.setAttribute('aria-pressed', 'false');
				}
			});

			// Region button labels flip + / − based on whether all countries
			// in that region are currently selected. Tells the user what the
			// next click will do.
			regionBtnElements.forEach(function (btn) {
				var key = btn.dataset.regionKey;
				var label = btn.dataset.regionLabel;
				var regionCodes = REGIONS[key] || [];
				if (regionCodes.length === 0) return;
				var allSelected = regionCodes.every(function (c) { return asMap[c]; });
				if (allSelected) {
					btn.textContent = '\u2212 ' + label; // "− Africa"
					btn.classList.add('is-active');
				} else {
					btn.textContent = '+ ' + label;
					btn.classList.remove('is-active');
				}
			});

			// Status line.
			var n = codes.length;
			if (n === 0) {
				status.textContent = 'No countries selected.';
			} else if (n === 1) {
				status.textContent = '1 country blocked: ' + codes[0];
			} else {
				status.textContent = n + ' countries blocked.';
			}
		}

		// Sync from textarea -> chips when user edits the textarea directly.
		textarea.addEventListener('input', refreshUI);

		refreshUI();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
