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
	import { KeyRound, Plus, Trash2, ChevronDown, ChevronRight, Copy, Check } from '@lucide/svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';

	const EXPIRY_WARN_MS = 14 * 24 * 60 * 60 * 1000;

	/** @type {import('$lib/api').APIKeyInfo[]} */
	let keys = $state([]);
	/** @type {import('$lib/api').APIKeyScopeInfo[]} */
	let scopeCatalog = $state([]);
	let loading = $state(true);
	let error = $state('');
	let search = $state('');

	/** @type {Set<string>} */
	let expandedTenants = $state(new Set());

	let showIssueModal = $state(false);
	let issuing = $state(false);
	let issueTenantId = $state('');
	let issueName = $state('');
	let issueAudience = $state(/** @type {'internal' | 'tenant'} */ ('tenant'));
	/** @type {Set<string>} */
	let issueScopes = $state(new Set());
	let issueExpiryMode = $state(/** @type {'default' | 'custom' | 'never'} */ ('default'));
	let issueExpiresIn = $state('');
	let issueRateLimit = $state('');

	let revealedKey = $state(/** @type {import('$lib/api').CreateAPIKeyResult | null} */ (null));
	let copied = $state(false);
	let revealAcknowledged = $state(false);

	let revokingKey = $state(/** @type {import('$lib/api').APIKeyInfo | null} */ (null));
	let showRevokeKeyConfirm = $state(false);

	let revokingTenant = $state(/** @type {{ tenantId: string, count: number } | null} */ (null));
	let showRevokeTenantConfirm = $state(false);

	let scopeOptions = $derived(
		scopeCatalog.map((s) => ({
			key: s.name,
			name: s.name,
			description: s.description
		}))
	);

	let activeKeys = $derived(keys.filter((k) => !k.revoked_at));

	/** @type {'name' | 'tenant_id' | 'audience' | 'scopes' | 'rate_limit' | 'expires_at' | 'last_used_at'} */
	let sortField = $state('name');
	let sortDirection = $state(/** @type {'asc' | 'desc'} */ ('asc'));

	/**
	 * @param {import('$lib/api').APIKeyInfo} key
	 * @param {typeof sortField} field
	 */
	function sortValue(key, field) {
		switch (field) {
			case 'name':
				return key.name.toLowerCase();
			case 'tenant_id':
				return key.tenant_id.toLowerCase();
			case 'audience':
				return (key.audience || 'any').toLowerCase();
			case 'scopes':
				return (key.scopes || []).slice().sort().join(',').toLowerCase();
			case 'rate_limit':
				return key.rate_limit && key.rate_limit > 0 ? key.rate_limit : -1;
			case 'expires_at': {
				if (!key.expires_at) return Number.POSITIVE_INFINITY;
				const at = Date.parse(key.expires_at);
				return Number.isNaN(at) ? Number.POSITIVE_INFINITY : at;
			}
			case 'last_used_at': {
				if (!key.last_used_at) return Number.NEGATIVE_INFINITY;
				const at = Date.parse(key.last_used_at);
				return Number.isNaN(at) ? Number.NEGATIVE_INFINITY : at;
			}
			default:
				return '';
		}
	}

	/**
	 * @param {import('$lib/api').APIKeyInfo} a
	 * @param {import('$lib/api').APIKeyInfo} b
	 */
	function compareKeys(a, b) {
		const av = sortValue(a, sortField);
		const bv = sortValue(b, sortField);
		let cmp = 0;
		if (typeof av === 'number' && typeof bv === 'number') {
			cmp = av - bv;
		} else {
			cmp = String(av).localeCompare(String(bv));
		}
		if (cmp === 0) {
			cmp = a.name.localeCompare(b.name) || a.id.localeCompare(b.id);
		}
		return sortDirection === 'asc' ? cmp : -cmp;
	}

	/** @param {typeof sortField} field */
	function handleSort(field) {
		if (sortField === field) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			sortField = field;
			sortDirection = 'asc';
		}
	}

	/** @param {typeof sortField} field */
	function sortAria(field) {
		if (sortField !== field) return 'none';
		return sortDirection === 'asc' ? 'ascending' : 'descending';
	}

	let tenantGroups = $derived.by(() => {
		// Touch sort state so this derived re-runs when headers are clicked.
		const field = sortField;
		const direction = sortDirection;
		/** @type {Map<string, import('$lib/api').APIKeyInfo[]>} */
		const map = new Map();
		for (const key of activeKeys) {
			const list = map.get(key.tenant_id) || [];
			list.push(key);
			map.set(key.tenant_id, list);
		}
		const q = search.trim().toLowerCase();
		const groups = [...map.entries()]
			.map(([tenantId, tenantKeys]) => ({
				tenantId,
				keys: tenantKeys.slice().sort(compareKeys)
			}))
			.filter((group) => {
				if (!q) return true;
				if (group.tenantId.toLowerCase().includes(q)) return true;
				return group.keys.some(
					(k) =>
						k.name.toLowerCase().includes(q) ||
						k.id.toLowerCase().includes(q) ||
						(k.audience || '').toLowerCase().includes(q) ||
						(k.scopes || []).some((s) => s.toLowerCase().includes(q))
				);
			});

		if (field === 'tenant_id') {
			groups.sort((a, b) => {
				const cmp = a.tenantId.localeCompare(b.tenantId);
				return direction === 'asc' ? cmp : -cmp;
			});
		} else {
			groups.sort((a, b) => a.tenantId.localeCompare(b.tenantId));
		}
		return groups;
	});

	let canIssue = $derived(
		issueTenantId.trim().length > 0 &&
			issueName.trim().length > 0 &&
			(issueAudience === 'internal' || issueAudience === 'tenant') &&
			issueScopes.size > 0 &&
			(issueExpiryMode !== 'custom' || issueExpiresIn.trim().length > 0) &&
			!issuing
	);

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
		issueAudience = 'tenant';
		issueScopes = new Set();
		issueExpiryMode = 'default';
		issueExpiresIn = '';
		issueRateLimit = '';
		showIssueModal = true;
	}

	function closeIssueModal() {
		showIssueModal = false;
	}

	/** @param {Set<string>} next */
	function onScopesChange(next) {
		issueScopes = next;
	}

	async function submitIssue() {
		if (!canIssue) return;
		issuing = true;
		try {
			/** @type {import('$lib/api').CreateAPIKeyInput} */
			const body = {
				tenant_id: issueTenantId.trim(),
				audience: issueAudience,
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

<div class="list-panel" data-testid="superuser-api-keys-panel">
	<div class="list-panel-header">
		<h2 class="section-title">API Keys</h2>
		<p class="section-subtitle">
			Per-caller credentials. <code class="text-xs">validate</code> covers
			<code class="text-xs">/validate</code>; <code class="text-xs">auth</code> skips Cap on public
			login/register/password-reset when Cap is enabled. Audience binds each key to the internal
			(mesh) or tenant (public) surface. Grouped by tenant so you can rotate one holder or revoke
			everything they have.
		</p>
	</div>

	{#if loading}
		<p class="text-muted" data-testid="api-keys-loading">Loading...</p>
	{:else if error}
		<p class="text-error" data-testid="api-keys-error">{error}</p>
	{:else}
		<div class="list-panel-body">
		<div class="flex flex-wrap items-end justify-between gap-3">
			<div class="flex min-w-0 flex-wrap items-end gap-3">
				<label class="form-label w-[28rem] max-w-full">
					<span>Search</span>
					<input
						type="search"
						class="input"
						placeholder="Search tenant, name, id, or scope…"
						data-testid="api-keys-search"
						bind:value={search}
					/>
				</label>
				<span class="text-sm text-muted pb-2" data-testid="api-keys-total">
					{activeKeys.length} active key{activeKeys.length === 1 ? '' : 's'} · {tenantGroups.length} tenant{tenantGroups.length === 1 ? '' : 's'}
				</span>
			</div>
			<button
				type="button"
				class="btn-primary shrink-0"
				data-testid="api-keys-issue"
				onclick={openIssueModal}
			>
				<Plus size={16} class="-ml-0.5" />
				Issue key
			</button>
		</div>

		{#if tenantGroups.length === 0}
			<p class="text-muted py-6" data-testid="api-keys-empty">
				No API keys yet. Issue one for an internal service or external tenant to call
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
								onclick={() => toggleTenant(group.tenantId)}
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
								class="btn-small border-error text-error"
								data-testid="api-keys-revoke-tenant"
								title="Revoke every key for this tenant"
								onclick={() => askRevokeTenant(group.tenantId, group.keys.length)}
							>
								Revoke all
							</button>
						</div>

						{#if expandedTenants.has(group.tenantId)}
							<div class="table-scroll" data-testid="api-keys-tenant-keys">
								<table class="table-base">
									<thead>
										<tr>
											<th aria-sort={sortAria('name')}>
												<button
													type="button"
													class="flex items-center gap-1 hover:text-accent transition-colors"
													data-testid="api-keys-sort-name"
													data-sort-active={sortField === 'name' ? 'true' : 'false'}
													data-sort-direction={sortField === 'name' ? sortDirection : ''}
													onclick={() => handleSort('name')}
												>
													Name
													{#if sortField === 'name'}
														<span class="text-xs" data-testid="api-keys-sort-indicator" aria-hidden="true"
															>{sortDirection === 'asc' ? '↑' : '↓'}</span
														>
													{/if}
												</button>
											</th>
											<th aria-sort={sortAria('tenant_id')}>
												<button
													type="button"
													class="flex items-center gap-1 hover:text-accent transition-colors"
													data-testid="api-keys-sort-tenant-id"
													data-sort-active={sortField === 'tenant_id' ? 'true' : 'false'}
													data-sort-direction={sortField === 'tenant_id' ? sortDirection : ''}
													onclick={() => handleSort('tenant_id')}
												>
													Tenant ID
													{#if sortField === 'tenant_id'}
														<span class="text-xs" data-testid="api-keys-sort-indicator" aria-hidden="true"
															>{sortDirection === 'asc' ? '↑' : '↓'}</span
														>
													{/if}
												</button>
											</th>
											<th aria-sort={sortAria('audience')}>
												<button
													type="button"
													class="flex items-center gap-1 hover:text-accent transition-colors"
													data-testid="api-keys-sort-audience"
													data-sort-active={sortField === 'audience' ? 'true' : 'false'}
													data-sort-direction={sortField === 'audience' ? sortDirection : ''}
													onclick={() => handleSort('audience')}
												>
													Audience
													{#if sortField === 'audience'}
														<span class="text-xs" data-testid="api-keys-sort-indicator" aria-hidden="true"
															>{sortDirection === 'asc' ? '↑' : '↓'}</span
														>
													{/if}
												</button>
											</th>
											<th aria-sort={sortAria('scopes')}>
												<button
													type="button"
													class="flex items-center gap-1 hover:text-accent transition-colors"
													data-testid="api-keys-sort-scopes"
													data-sort-active={sortField === 'scopes' ? 'true' : 'false'}
													data-sort-direction={sortField === 'scopes' ? sortDirection : ''}
													onclick={() => handleSort('scopes')}
												>
													Scopes
													{#if sortField === 'scopes'}
														<span class="text-xs" data-testid="api-keys-sort-indicator" aria-hidden="true"
															>{sortDirection === 'asc' ? '↑' : '↓'}</span
														>
													{/if}
												</button>
											</th>
											<th aria-sort={sortAria('rate_limit')}>
												<button
													type="button"
													class="flex items-center gap-1 hover:text-accent transition-colors"
													data-testid="api-keys-sort-rate-limit"
													data-sort-active={sortField === 'rate_limit' ? 'true' : 'false'}
													data-sort-direction={sortField === 'rate_limit' ? sortDirection : ''}
													onclick={() => handleSort('rate_limit')}
												>
													Rate limit
													{#if sortField === 'rate_limit'}
														<span class="text-xs" data-testid="api-keys-sort-indicator" aria-hidden="true"
															>{sortDirection === 'asc' ? '↑' : '↓'}</span
														>
													{/if}
												</button>
											</th>
											<th aria-sort={sortAria('expires_at')}>
												<button
													type="button"
													class="flex items-center gap-1 hover:text-accent transition-colors"
													data-testid="api-keys-sort-expires"
													data-sort-active={sortField === 'expires_at' ? 'true' : 'false'}
													data-sort-direction={sortField === 'expires_at' ? sortDirection : ''}
													onclick={() => handleSort('expires_at')}
												>
													Expires
													{#if sortField === 'expires_at'}
														<span class="text-xs" data-testid="api-keys-sort-indicator" aria-hidden="true"
															>{sortDirection === 'asc' ? '↑' : '↓'}</span
														>
													{/if}
												</button>
											</th>
											<th aria-sort={sortAria('last_used_at')}>
												<button
													type="button"
													class="flex items-center gap-1 hover:text-accent transition-colors"
													data-testid="api-keys-sort-last-used"
													data-sort-active={sortField === 'last_used_at' ? 'true' : 'false'}
													data-sort-direction={sortField === 'last_used_at' ? sortDirection : ''}
													onclick={() => handleSort('last_used_at')}
												>
													Last used
													{#if sortField === 'last_used_at'}
														<span class="text-xs" data-testid="api-keys-sort-indicator" aria-hidden="true"
															>{sortDirection === 'asc' ? '↑' : '↓'}</span
														>
													{/if}
												</button>
											</th>
											<th class="sr-only">Actions</th>
										</tr>
									</thead>
									<tbody>
										{#each group.keys as key (key.id)}
											<tr
												data-testid="api-keys-row"
												data-key-id={key.id}
												data-key-name={key.name}
												data-tenant-id={key.tenant_id}
											>
												<td>
													<div class="font-medium">{key.name}</div>
													<div class="text-xs text-muted font-mono">{key.id}</div>
												</td>
												<td class="font-mono text-xs" data-testid="api-keys-row-tenant-id">
													{key.tenant_id}
												</td>
												<td data-testid="api-keys-row-audience">
													{#if key.audience}
														<span class="ms-chip text-xs px-2 py-0.5">{key.audience}</span>
													{:else}
														<span class="text-muted text-xs" title="Pre-audience key; accepted on any surface until re-issued">any</span>
													{/if}
												</td>
												<td>
													<div class="flex flex-wrap gap-1" data-testid="api-keys-row-scopes">
														{#each key.scopes || [] as scope}
															<span class="ms-chip badge-scope text-xs px-2 py-0.5">{scope}</span>
														{/each}
													</div>
												</td>
												<td data-testid="api-keys-row-rate-limit">
													{#if key.rate_limit && key.rate_limit > 0}
														{key.rate_limit}/min
													{:else}
														<span class="text-muted">Default</span>
													{/if}
												</td>
												<td data-testid="api-keys-row-expires">
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
												<td class="text-muted" data-testid="api-keys-row-last-used">
													{key.last_used_at ? formatRelative(key.last_used_at) : 'never'}
												</td>
												<td class="text-right">
													<button
														type="button"
														class="btn-icon-danger"
														data-testid="api-keys-revoke"
														title="Revoke this key"
														onclick={() => askRevokeKey(key)}
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
		</div>
	{/if}
</div>

<Modal
	bind:open={showIssueModal}
	title="Issue API key"
	labelledBy="api-keys-issue-title"
	wide
	onClose={closeIssueModal}
>
	<form
		class="space-y-4"
		data-testid="api-keys-issue-modal"
		onsubmit={(e) => {
			e.preventDefault();
			void submitIssue();
		}}
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
		<div>
			<span class="form-label">Audience</span>
			<p class="text-xs text-muted mb-2">
				Which /validate surface may accept this key. Internal is the private service listener;
				tenant is the public edge when published.
			</p>
			<div class="flex flex-wrap gap-3" data-testid="api-keys-issue-audience">
				<label class="inline-flex items-center gap-2 text-sm">
					<input
						type="radio"
						name="api-key-audience"
						value="tenant"
						bind:group={issueAudience}
						data-testid="api-keys-issue-audience-tenant"
					/>
					Tenant (public)
				</label>
				<label class="inline-flex items-center gap-2 text-sm">
					<input
						type="radio"
						name="api-key-audience"
						value="internal"
						bind:group={issueAudience}
						data-testid="api-keys-issue-audience-internal"
					/>
					Internal (mesh)
				</label>
			</div>
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
				onChange={onScopesChange}
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
	{#snippet footer()}
		<div class="flex justify-end gap-3">
			<button
				type="button"
				class="btn-secondary"
				data-testid="api-keys-issue-cancel"
				onclick={closeIssueModal}
			>
				Cancel
			</button>
			<button
				type="button"
				class="btn-primary"
				data-testid="api-keys-issue-submit"
				disabled={!canIssue}
				onclick={submitIssue}
			>
				{issuing ? 'Issuing…' : 'Issue key'}
			</button>
		</div>
	{/snippet}
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
					{revealedKey.tenant_id} · {revealedKey.audience || 'any'} · {revealedKey.name}
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
						onclick={copyRevealedKey}
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
	{#snippet footer()}
		<div class="flex justify-end">
			<button
				type="button"
				class="btn-primary"
				data-testid="api-keys-reveal-done"
				disabled={!revealAcknowledged}
				onclick={closeRevealModal}
			>
				Done
			</button>
		</div>
	{/snippet}
</Modal>

<ConfirmModal
	bind:open={showRevokeKeyConfirm}
	title="Revoke API key"
	message={revokingKey
		? `Revoke "${revokingKey.name}" (${revokingKey.id}) for tenant ${revokingKey.tenant_id}?\n\nThe caller will be refused on its next /validate request.`
		: ''}
	confirmText="Revoke"
	confirmClass="btn-danger"
	onConfirm={confirmRevokeKey}
	onCancel={() => {
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
	onConfirm={confirmRevokeTenant}
	onCancel={() => {
		revokingTenant = null;
	}}
/>
