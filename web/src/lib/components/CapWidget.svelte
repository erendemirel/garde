<script>
	import { onMount, onDestroy } from 'svelte';
	import 'cap-widget';
	import { getCaptchaConfig } from '$lib/api';

	/**
	 * @typedef {'always' | 'progressive'} CapMode
	 * @type {{
	 *   token?: string,
	 *   active?: boolean,
	 *   ready?: boolean,
	 *   mode?: CapMode,
	 *   required?: boolean
	 * }}
	 */
	let {
		token = $bindable(''),
		active = $bindable(false),
		ready = $bindable(false),
		mode = 'always',
		required = $bindable(false)
	} = $props();

	let enabled = $state(false);
	let widgetEndpoint = $state('');
	let loading = $state(true);
	let error = $state('');
	/** Bumped when a solved token is cleared so the widget remounts (single-use tokens). */
	let widgetKey = $state(0);
	let hadSolvedToken = $state(false);

	$effect(() => {
		if (!enabled) {
			active = false;
			return;
		}
		if (mode === 'progressive') {
			active = required;
		} else {
			active = true;
			required = true;
		}
	});

	// Parents clear `token` after a failed submit. Cap stays visually solved unless remounted,
	// which would leave the form blocked (active && !token) until a full page refresh.
	$effect(() => {
		if (token) {
			hadSolvedToken = true;
			return;
		}
		if (hadSolvedToken) {
			hadSolvedToken = false;
			error = '';
			widgetKey += 1;
		}
	});

	/**
	 * Cap dispatches solve/error/reset with bubbles+composed; host the listeners
	 * on this wrap (regular element — actions are reliable here).
	 * @param {HTMLElement} node
	 */
	function captchaHost(node) {
		/** @param {Event} e */
		function onSolve(e) {
			const detail = /** @type {CustomEvent<{ token?: string }>} */ (e).detail;
			token = detail?.token || '';
		}
		/** @param {Event} e */
		function onError(e) {
			const detail = /** @type {CustomEvent<{ message?: string }>} */ (e).detail;
			error = detail?.message || 'Captcha failed';
			token = '';
		}
		function onReset() {
			token = '';
		}

		node.addEventListener('solve', onSolve);
		node.addEventListener('error', onError);
		node.addEventListener('reset', onReset);

		/** @type {any} */
		const w = window;
		w.__gardeCapSetToken = (/** @type {string} */ tok) => {
			token = typeof tok === 'string' ? tok : '';
		};

		return {
			destroy() {
				node.removeEventListener('solve', onSolve);
				node.removeEventListener('error', onError);
				node.removeEventListener('reset', onReset);
				if (w.__gardeCapSetToken) delete w.__gardeCapSetToken;
			}
		};
	}

	onMount(async () => {
		try {
			const cfg = await getCaptchaConfig();
			enabled = !!cfg.enabled;
			widgetEndpoint = cfg.widget_endpoint || '';
			if (mode === 'progressive') {
				required = !!cfg.login_required;
			} else {
				required = enabled;
			}
			if (enabled && !widgetEndpoint) {
				error = 'Captcha is enabled but not configured';
			}
		} catch (e) {
			// Cap is optional — leave forms usable when the config endpoint fails.
			enabled = false;
			active = false;
			required = false;
		} finally {
			loading = false;
			ready = true;
		}
	});

	onDestroy(() => {
		token = '';
	});
</script>

{#if loading}
	<p class="text-sm text-muted" data-testid="cap-loading">Loading captcha...</p>
{:else if enabled && (mode !== 'progressive' || required)}
	<div
		class="cap-wrap"
		use:captchaHost
		data-testid="cap-widget-wrap"
		data-solved={token ? 'true' : 'false'}
	>
		{#if widgetEndpoint}
			{#key widgetKey}
				<cap-widget
					data-cap-api-endpoint={widgetEndpoint}
					data-testid="cap-widget"
				></cap-widget>
			{/key}
		{/if}
		{#if error}
			<p class="error text-sm" data-testid="cap-error">{error}</p>
		{/if}
	</div>
{/if}

<style>
	.cap-wrap {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		align-items: flex-start;
	}

	.cap-wrap :global(cap-widget) {
		--cap-background: var(--surface, #fdfdfd);
		--cap-border-color: var(--borderc, #dddddd8f);
		--cap-color: var(--ink, #212121);
		--cap-font: inherit;
		width: 100%;
	}
</style>
