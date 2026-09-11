<script>
	import { onMount } from 'svelte';
	import {
		listAPIKeyScopes,
		listAPIKeys,
		createAPIKey,
		revokeAPIKey,
		revokeTenantAPIKeys
	} from '$lib/api';
	import { showToast } from '$lib/toast';
	import { KeyRound, Plus, Trash2, ChevronDown, ChevronRight, Copy, Check } from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';

	const EXPIRY_WARN_MS = 14 * 24 * 60 * 60 * 1000;

	/** @type {import('$lib/api').APIKeyInfo[]} */
	let keys = [];
	/** @type {import('$lib/api').APIKeyScopeInfo[]} */
	let scopeCatalog = [];
	let loading = true;
	let error = '';
	let search = '';

	/** @type {Set<string>} */
	let expandedTenants = new Set();

	let showIssueModal = false;
	let issuing = false;
	let issueTenantId = '';
	let issueName = '';
	/** @type {Set<string>} */
	let issueScopes = new Set();
	/** @type {'default' | 'custom' | 'never'} */
	let issueExpiryMode = 'default';
	let issueExpiresIn = '';
	let issueRateLimit = '';

	/** @type {import('$lib/api').CreateAPIKeyResult | null} */
	let revealedKey = null;
	let copied = false;
	let revealAcknowledged = false;

	/** @type {import('$lib/api').APIKeyInfo | null} */
	let revokingKey = null;
	let showRevokeKeyConfirm = false;

	/** @type {{ tenantId: string, count: number } | null} */
	let revokingTenant = null;
	let showRevokeTenantConfirm = false;

	$: scopeOptions = scopeCatalog.map((s) => ({
		key: s.name,
		name: s.name,
		description: s.description
	}));

	$: activeKeys = keys.filter((k) => !k.revoked_at);

	$: tenantGroups = (() => {
		/** @type {Map<string, import('$lib/api').APIKeyInfo[]>} */
		const map = new Map();
		for (const key of activeKeys) {
			const list = map.get(key.tenant_id) || [];
			list.push(key);
			map.set(key.tenant_id, list);
		}
		const q = search.trim().toLowerCase();
		return [...map.entries()]
			.map(([tenantId, tenantKeys]) => ({
				tenantId,
				keys: tenantKeys.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
			}))
			.filter((group) => {
				if (!q) return true;
				if (group.tenantId.toLowerCase().includes(q)) return true;
				return group.keys.some(
					(k) =>
						k.name.toLowerCase().includes(q) ||
						k.id.toLowerCase().includes(q) ||
						(k.scopes || []).some((s) => s.toLowerCase().includes(q))
				);
			})
			.sort((a, b) => a.tenantId.localeCompare(b.tenantId));
	})();

	$: canIssue =
		issueTenantId.trim().length > 0 &&
		issueName.trim().length > 0 &&
		issueScopes.size > 0 &&
		(issueExpiryMode !== 'custom' || issueExpiresIn.trim().length > 0) &&
		!issuing;

	onMount(() => {
		load();
	});

	async function load() {
		loading = true;
		error = '';
		try {
			const [listed, scopes] = await Promise.all([listAPIKeys(), listAPIKeyScopes()]);
			keys = listed.keys || [];
			scopeCatalog = scopes || [];
			// Expand every tenant on first load so a small list is immediately useful.
			if (expandedTenants.size === 0) {
				expandedTenants = new Set((listed.keys || []).map((k) => k.tenant_id));
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load API keys';
			keys = [];
		} finally {
			loading = false;
		}
	}

	function toggleTenant(/** @type {string} */ tenantId) {
		const next = new Set(expandedTenants);
		if (next.has(tenantId)) next.delete(tenantId);
		else next.add(tenantId);
		expandedTenants = next;
	}

	function openIssueModal() {
		issueTenantId = '';
		issueName = '';
		issueScopes = new Set();
		issueExpiryMode = 'default';
		issueExpiresIn = '';
		issueRateLimit = '';
		showIssueModal = true;
	}

	function closeIssueModal() {
		showIssueModal = false;
	}

	/** @param {CustomEvent<Set<string>>} e */
	function onScopesChange(e) {
		issueScopes = e.detail;
	}

	async function submitIssue() {
		if (!canIssue) return;
		issuing = true;
		try {
			/** @type {import('$lib/api').CreateAPIKeyInput} */
			const body = {
				tenant_id: issueTenantId.trim(),
				name: issueName.trim(),
				scopes: [...issueScopes]
			};
			if (issueExpiryMode === 'never') {
				body.never_expires = true;
			} else if (issueExpiryMode === 'custom') {
				body.expires_in = issueExpiresIn.trim();
			}
			const rate = Number(issueRateLimit);
			if (issueRateLimit.trim() !== '' && Number.isFinite(rate) && rate > 0) {
				body.rate_limit = Math.floor(rate);
			}

			const created = await createAPIKey(body);
			showIssueModal = false;
			revealedKey = created;
			copied = false;
			revealAcknowledged = false;
			showToast(`Issued key "${created.name}" for ${created.tenant_id}`, 'success');
			await load();
			expandedTenants = new Set([...expandedTenants, created.tenant_id]);
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to issue API key', 'error');
		} finally {
			issuing = false;
		}
	}

	async function copyRevealedKey() {
		if (!revealedKey?.key) return;
		try {
			await navigator.clipboard.writeText(revealedKey.key);
			copied = true;
			showToast('API key copied to clipboard', 'success');
		} catch {
			showToast('Could not copy — select the key and copy manually', 'error');
		}
	}

	function closeRevealModal() {
		if (!revealAcknowledged) return;
		revealedKey = null;
		copied = false;
		revealAcknowledged = false;
	}

	function askRevokeKey(/** @type {import('$lib/api').APIKeyInfo} */ key) {
		revokingKey = key;
		showRevokeKeyConfirm = true;
	}

	async function confirmRevokeKey() {
		if (!revokingKey) return;
		const key = revokingKey;
		revokingKey = null;
		try {
			await revokeAPIKey(key.id);
			showToast(`Revoked key "${key.name}"`, 'success');
			await load();
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to revoke key', 'error');
		}
	}

	function askRevokeTenant(/** @type {string} */ tenantId, /** @type {number} */ count) {
		revokingTenant = { tenantId, count };
		showRevokeTenantConfirm = true;
	}

	async function confirmRevokeTenant() {
		if (!revokingTenant) return;
		const { tenantId, count } = revokingTenant;
		revokingTenant = null;
		try {
			await revokeTenantAPIKeys(tenantId);
			// Use the active count shown in the confirm dialog — the API also
			// reports already-revoked siblings (idempotent), which would inflate
			// the toast past what the operator just agreed to wipe.
			showToast(`Revoked ${count} key(s) for ${tenantId}`, 'success');
			await load();
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to revoke tenant keys', 'error');
		}
	}

	/**
	 * @param {string | null | undefined} iso
	 * @returns {'ok' | 'soon' | 'expired' | 'none'}
	 */
	function expiryState(iso) {
		if (!iso) return 'none';
		const at = Date.parse(iso);
		if (Number.isNaN(at)) return 'none';
		const remaining = at - Date.now();
		if (remaining <= 0) return 'expired';
		if (remaining <= EXPIRY_WARN_MS) return 'soon';
		return 'ok';
	}

	/** @param {string | null | undefined} iso */
	function formatWhen(iso) {
		if (!iso) return '—';
		const at = Date.parse(iso);
		if (Number.isNaN(at)) return '—';
		return new Date(at).toLocaleString();
	}

	/** @param {string | null | undefined} iso */
	function formatRelative(iso) {
		if (!iso) return 'never';
		const at = Date.parse(iso);
		if (Number.isNaN(at)) return '—';
		const delta = at - Date.now();
		const abs = Math.abs(delta);
		const day = 24 * 60 * 60 * 1000;
		if (abs < day) {
			const hours = Math.max(1, Math.round(abs / (60 * 60 * 1000)));
			return delta < 0 ? `${hours}h ago` : `in ${hours}h`;
		}
		const days = Math.round(abs / day);
		return delta < 0 ? `${days}d ago` : `in ${days}d`;
	}
</script>

<div class="space-y-4" data-testid="superuser-api-keys-panel">
	<div class="flex flex-wrap items-start justify-between gap-3">
		<div>
			<h2 class="section-title">API Keys</h2>
			<p class="text-sm text-muted mt-1">
				Per-caller credentials for external <code class="text-xs">/validate</code> traffic. Grouped by
				tenant so you can rotate one holder or revoke everything they have. Scopes are enforced by
				garde — unlike permissions, which other apps interpret.
			</p>
		</div>
		<button
			type="button"
			class="btn-primary"
			data-testid="api-keys-issue"
			on:click={openIssueModal}
		>
			<Plus size={16} class="inline mr-1" />
			Issue key
		</button>
	</div>

	{#if loading}
		<p class="text-muted" data-testid="api-keys-loading">Loading...</p>
	{:else if error}
		<p class="text-error" data-testid="api-keys-error">{error}</p>
	{:else}
		<div class="flex flex-wrap gap-3 items-center">
			<input
				type="search"
				class="input max-w-sm"
				placeholder="Search tenant, name, id, or scope…"
				data-testid="api-keys-search"
				bind:value={search}
			/>
			<span class="text-sm text-muted" data-testid="api-keys-total">
				{activeKeys.length} active key{activeKeys.length === 1 ? '' : 's'} · {tenantGroups.length} tenant{tenantGroups.length === 1 ? '' : 's'}
			</span>
		</div>

		{#if tenantGroups.length === 0}
			<p class="text-muted py-6" data-testid="api-keys-empty">
				No API keys yet. Issue one to give an external caller its own credential for
				<code class="text-xs">/validate</code>.
			</p>
		{:else}
			<div class="space-y-3" data-testid="api-keys-tenant-list">
				{#each tenantGroups as group (group.tenantId)}
					<div
						class="border border-borderc rounded-md overflow-hidden"
						data-testid="api-keys-tenant"
						data-tenant-id={group.tenantId}
						data-expanded={expandedTenants.has(group.tenantId) ? 'true' : 'false'}
					>
						<div class="flex flex-wrap items-center gap-2 px-3 py-2 bg-input/60">
							<button
								type="button"
								class="flex items-center gap-2 font-medium text-left flex-1 min-w-0"
								data-testid="api-keys-tenant-toggle"
								aria-expanded={expandedTenants.has(group.tenantId)}
								on:click={() => toggleTenant(group.tenantId)}
							>
								{#if expandedTenants.has(group.tenantId)}
									<ChevronDown size={16} class="shrink-0" />
								{:else}
									<ChevronRight size={16} class="shrink-0" />
								{/if}
								<KeyRound size={16} class="shrink-0 text-muted" />
								<span class="truncate" data-testid="api-keys-tenant-id">{group.tenantId}</span>
								<span class="text-sm text-muted shrink-0">
									{group.keys.length} key{group.keys.length === 1 ? '' : 's'}
								</span>
							</button>
							<button
								type="button"
								class="btn-small text-error border-error/40"
								data-testid="api-keys-revoke-tenant"
								title="Revoke every key for this tenant"
								on:click={() => askRevokeTenant(group.tenantId, group.keys.length)}
							>
								Revoke all
							</button>
						</div>

						{#if expandedTenants.has(group.tenantId)}
							<div class="overflow-x-auto" data-testid="api-keys-tenant-keys">
								<table class="w-full text-sm">
									<thead>
										<tr class="text-left text-muted border-t border-borderc">
											<th class="px-3 py-2 font-medium">Name</th>
											<th class="px-3 py-2 font-medium">Scopes</th>
											<th class="px-3 py-2 font-medium">Expires</th>
											<th class="px-3 py-2 font-medium">Last used</th>
											<th class="px-3 py-2 font-medium sr-only">Actions</th>
										</tr>
									</thead>
									<tbody>
										{#each group.keys as key (key.id)}
											<tr
												class="border-t border-borderc"
												data-testid="api-keys-row"
												data-key-id={key.id}
												data-key-name={key.name}
												data-tenant-id={key.tenant_id}
											>
												<td class="px-3 py-2">
													<div class="font-medium">{key.name}</div>
													<div class="text-xs text-muted font-mono">{key.id}</div>
												</td>
												<td class="px-3 py-2">
													<div class="flex flex-wrap gap-1" data-testid="api-keys-row-scopes">
														{#each key.scopes || [] as scope}
															<span class="ms-chip badge-scope text-xs px-2 py-0.5">{scope}</span>
														{/each}
													</div>
												</td>
												<td class="px-3 py-2" data-testid="api-keys-row-expires">
													{#if expiryState(key.expires_at) === 'none'}
														<span class="text-muted" data-expiry="never">Never</span>
													{:else}
														<span
															class="inline-flex flex-col gap-0.5"
															data-expiry={expiryState(key.expires_at)}
														>
															<span
																class={expiryState(key.expires_at) === 'soon' ||
																expiryState(key.expires_at) === 'expired'
																	? 'text-error font-medium'
																	: ''}
																data-testid="api-keys-expiry-label"
															>
																{formatRelative(key.expires_at)}
																{#if expiryState(key.expires_at) === 'soon'}
																	<span
																		class="ml-1 text-xs uppercase tracking-wide"
																		data-testid="api-keys-expiry-badge"
																		>Expiring soon</span
																	>
																{:else if expiryState(key.expires_at) === 'expired'}
																	<span
																		class="ml-1 text-xs uppercase tracking-wide"
																		data-testid="api-keys-expiry-badge"
																		>Expired</span
																	>
																{/if}
															</span>
															<span class="text-xs text-muted">{formatWhen(key.expires_at)}</span>
														</span>
													{/if}
												</td>
												<td class="px-3 py-2 text-muted" data-testid="api-keys-row-last-used">
													{key.last_used_at ? formatRelative(key.last_used_at) : 'never'}
												</td>
												<td class="px-3 py-2 text-right">
													<button
														type="button"
														class="btn-icon-danger"
														data-testid="api-keys-revoke"
														title="Revoke this key"
														on:click={() => askRevokeKey(key)}
													>
														<Trash2 size={16} />
													</button>
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	{/if}
</div>

<Modal
	bind:open={showIssueModal}
	title="Issue API key"
	labelledBy="api-keys-issue-title"
	wide
	on:close={closeIssueModal}
>
	<form
		class="space-y-4"
		data-testid="api-keys-issue-modal"
		on:submit|preventDefault={submitIssue}
	>
		<div>
			<label class="form-label" for="api-keys-issue-tenant">Tenant ID</label>
			<input
				id="api-keys-issue-tenant"
				class="input w-full"
				data-testid="api-keys-issue-tenant"
				placeholder="acme"
				autocomplete="off"
				bind:value={issueTenantId}
			/>
			<p class="text-xs text-muted mt-1">
				Names the holder. Several keys can share one tenant for rotation; revoke-all targets this
				id.
			</p>
		</div>
		<div>
			<label class="form-label" for="api-keys-issue-name">Key name</label>
			<input
				id="api-keys-issue-name"
				class="input w-full"
				data-testid="api-keys-issue-name"
				placeholder="acme-prod"
				autocomplete="off"
				bind:value={issueName}
			/>
		</div>
		<div data-testid="api-keys-issue-scopes">
			<span class="form-label">Scopes</span>
			<p class="text-xs text-muted mb-2">
				Enforced by garde on each request. Nothing is selected by default — pick at least one.
			</p>
			<MultiSelectChips
				variant="scope"
				label="Scopes"
				placeholder="Add a scope…"
				options={scopeOptions}
				selected={issueScopes}
				initial={new Set()}
				on:change={onScopesChange}
			/>
		</div>
		<div>
			<span class="form-label">Lifetime</span>
			<div class="flex flex-wrap gap-3 mt-1" data-testid="api-keys-issue-expiry-mode">
				<label class="inline-flex items-center gap-2 text-sm">
					<input
						type="radio"
						name="api-key-expiry"
						value="default"
						bind:group={issueExpiryMode}
						data-testid="api-keys-issue-expiry-default"
					/>
					90 days (default)
				</label>
				<label class="inline-flex items-center gap-2 text-sm">
					<input
						type="radio"
						name="api-key-expiry"
						value="custom"
						bind:group={issueExpiryMode}
						data-testid="api-keys-issue-expiry-custom"
					/>
					Custom duration
				</label>
				<label class="inline-flex items-center gap-2 text-sm">
					<input
						type="radio"
						name="api-key-expiry"
						value="never"
						bind:group={issueExpiryMode}
						data-testid="api-keys-issue-expiry-never"
					/>
					Never expires
				</label>
			</div>
			{#if issueExpiryMode === 'custom'}
				<input
					class="input w-full mt-2"
					data-testid="api-keys-issue-expires-in"
					placeholder="e.g. 720h (Go duration, max 8760h)"
					bind:value={issueExpiresIn}
				/>
			{/if}
		</div>
		<div>
			<label class="form-label" for="api-keys-issue-rate">Rate limit (optional)</label>
			<input
				id="api-keys-issue-rate"
				class="input w-full"
				type="number"
				min="1"
				data-testid="api-keys-issue-rate-limit"
				placeholder="Requests per window; leave blank for the authenticated tier default"
				bind:value={issueRateLimit}
			/>
		</div>
	</form>
	<div slot="footer" class="flex justify-end gap-3">
		<button
			type="button"
			class="btn-secondary"
			data-testid="api-keys-issue-cancel"
			on:click={closeIssueModal}
		>
			Cancel
		</button>
		<button
			type="button"
			class="btn-primary"
			data-testid="api-keys-issue-submit"
			disabled={!canIssue}
			on:click={submitIssue}
		>
			{issuing ? 'Issuing…' : 'Issue key'}
		</button>
	</div>
</Modal>

<Modal
	open={!!revealedKey}
	title="Save this API key"
	labelledBy="api-keys-reveal-title"
	wide
	dismissible={false}
	preferDialogFocus
>
	{#if revealedKey}
		<div class="space-y-4" data-testid="api-keys-reveal-modal">
			<p class="text-sm text-error font-medium" data-testid="api-keys-reveal-warning">
				This is the only time the secret is shown. It cannot be retrieved again — if you lose it,
				issue a new key and revoke this one.
			</p>
			<div>
				<div class="text-xs text-muted mb-1">
					{revealedKey.tenant_id} · {revealedKey.name}
				</div>
				<div class="flex gap-2 items-stretch">
					<code
						class="input flex-1 font-mono text-xs break-all select-all"
						data-testid="api-keys-reveal-secret">{revealedKey.key}</code
					>
					<button
						type="button"
						class="btn-secondary shrink-0"
						data-testid="api-keys-reveal-copy"
						on:click={copyRevealedKey}
					>
						{#if copied}
							<Check size={16} />
						{:else}
							<Copy size={16} />
						{/if}
					</button>
				</div>
			</div>
			<label class="inline-flex items-start gap-2 text-sm" data-testid="api-keys-reveal-ack-label">
				<input
					type="checkbox"
					data-testid="api-keys-reveal-ack"
					bind:checked={revealAcknowledged}
				/>
				<span>I have saved this key somewhere safe</span>
			</label>
		</div>
	{/if}
	<div slot="footer" class="flex justify-end">
		<button
			type="button"
			class="btn-primary"
			data-testid="api-keys-reveal-done"
			disabled={!revealAcknowledged}
			on:click={closeRevealModal}
		>
			Done
		</button>
	</div>
</Modal>

<ConfirmModal
	bind:open={showRevokeKeyConfirm}
	title="Revoke API key"
	message={revokingKey
		? `Revoke "${revokingKey.name}" (${revokingKey.id}) for tenant ${revokingKey.tenant_id}?\n\nThe caller will be refused on its next /validate request.`
		: ''}
	confirmText="Revoke"
	confirmClass="btn-danger"
	on:confirm={confirmRevokeKey}
	on:cancel={() => {
		revokingKey = null;
	}}
/>

<ConfirmModal
	bind:open={showRevokeTenantConfirm}
	title="Revoke all keys for tenant"
	message={revokingTenant
		? `Revoke all ${revokingTenant.count} active key(s) for tenant "${revokingTenant.tenantId}"?\n\nEvery credential that holder has will stop working immediately.`
		: ''}
	confirmText="Revoke all"
	confirmClass="btn-danger"
	on:confirm={confirmRevokeTenant}
	on:cancel={() => {
		revokingTenant = null;
	}}
/>
