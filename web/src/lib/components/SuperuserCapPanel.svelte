<script>
	import { onMount } from 'svelte';
	import { ShieldCheck, ExternalLink } from '@lucide/svelte';
	import { getCaptchaAdminStatus } from '$lib/api';

	/** @type {{
	 *   enabled?: boolean,
	 *   site_key?: string,
	 *   public_url?: string,
	 *   api_url?: string,
	 *   widget_endpoint?: string,
	 *   secret_configured?: boolean,
	 *   dashboard_url?: string,
	 *   login_progressive?: boolean,
	 *   login_failure_threshold?: number
	 * } | null} */
	let status = $state(null);
	let loading = $state(true);
	let error = $state('');

	onMount(async () => {
		try {
			status = await getCaptchaAdminStatus();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load Cap status';
		} finally {
			loading = false;
		}
	});
</script>

<div class="space-y-4" data-testid="superuser-cap-panel">
	<div>
		<h2 class="section-title">
			<ShieldCheck size={20} class="inline mr-2" />
			Cap Captcha
		</h2>
		<p class="text-sm text-muted mt-1">
			Proof-of-work captcha: always on for register and password-reset; on login only after a
			failed attempt. Managed by Cap Standalone; garde verifies tokens server-side.
		</p>
	</div>

	{#if loading}
		<p class="text-muted" data-testid="cap-admin-loading">Loading...</p>
	{:else if error}
		<p class="error" data-testid="cap-admin-error">{error}</p>
	{:else if status}
		<dl class="grid gap-3 text-sm" data-testid="cap-admin-status">
			<div class="flex justify-between gap-4 border-b border-borderc pb-2">
				<dt class="text-muted font-medium">Status</dt>
				<dd data-testid="cap-admin-enabled">
					{#if status.enabled}
						<span class="text-success font-semibold">Enabled</span>
					{:else}
						<span class="text-muted font-semibold">Disabled</span>
					{/if}
				</dd>
			</div>
			<div class="flex justify-between gap-4 border-b border-borderc pb-2">
				<dt class="text-muted font-medium">Login policy</dt>
				<dd data-testid="cap-admin-login-policy">
					{#if status.login_progressive}
						Progressive (after {status.login_failure_threshold ?? 1} failure)
					{:else}
						—
					{/if}
				</dd>
			</div>
			<div class="flex justify-between gap-4 border-b border-borderc pb-2">
				<dt class="text-muted font-medium">Site key</dt>
				<dd class="font-mono text-xs break-all" data-testid="cap-admin-site-key">
					{status.site_key || '—'}
				</dd>
			</div>
			<div class="flex justify-between gap-4 border-b border-borderc pb-2">
				<dt class="text-muted font-medium">Secret configured</dt>
				<dd data-testid="cap-admin-secret">
					{status.secret_configured ? 'Yes' : 'No'}
				</dd>
			</div>
			<div class="flex justify-between gap-4 border-b border-borderc pb-2">
				<dt class="text-muted font-medium">Public URL</dt>
				<dd class="font-mono text-xs break-all" data-testid="cap-admin-public-url">
					{status.public_url || '—'}
				</dd>
			</div>
			<div class="flex justify-between gap-4 border-b border-borderc pb-2">
				<dt class="text-muted font-medium">Internal API URL</dt>
				<dd class="font-mono text-xs break-all" data-testid="cap-admin-api-url">
					{status.api_url || '—'}
				</dd>
			</div>
			<div class="flex justify-between gap-4 border-b border-borderc pb-2">
				<dt class="text-muted font-medium">Widget endpoint</dt>
				<dd class="font-mono text-xs break-all" data-testid="cap-admin-widget-endpoint">
					{status.widget_endpoint || '—'}
				</dd>
			</div>
		</dl>

		{#if status.dashboard_url}
			<a
				class="btn-secondary inline-flex items-center gap-2"
				href={status.dashboard_url}
				target="_blank"
				rel="noopener noreferrer"
				data-testid="cap-admin-dashboard-link"
			>
				Open Cap dashboard
				<ExternalLink size={16} />
			</a>
		{/if}

		<div class="rounded-md border border-borderc p-4 text-sm space-y-2">
			<p class="font-semibold">Enable Cap</p>
			<ol class="list-decimal list-inside space-y-1 text-muted">
				<li>Open the Cap dashboard and sign in with <code class="font-mono text-xs">CAP_ADMIN_KEY</code>.</li>
				<li>Create a site key (keep instrumentation on).</li>
				<li>
					Set Vault secrets <code class="font-mono text-xs">cap_enabled=true</code>,
					<code class="font-mono text-xs">cap_site_key</code>,
					<code class="font-mono text-xs">cap_secret_key</code>,
					<code class="font-mono text-xs">cap_api_url</code>, and
					<code class="font-mono text-xs">cap_public_url</code>.
				</li>
				<li>Secrets hot-reload; register/reset show the widget immediately; login shows it after a failed attempt.</li>
			</ol>
		</div>
	{/if}
</div>
