<script>
	import { onMount } from 'svelte';
	import { listPATs, createPAT, revokePAT } from '$lib/api';
	import { showToast } from '$lib/toast';
	import { ArrowLeft, Plus, Trash2, Copy, Check, KeyRound } from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';

	/** @type {import('$lib/api').PATInfo[]} */
	let tokens = [];
	let loading = true;
	let error = '';

	let showIssueModal = false;
	let issuing = false;
	let issueName = '';
	/** @type {'default' | 'custom' | 'never'} */
	let issueExpiryMode = 'default';
	let issueExpiresIn = '';

	/** @type {import('$lib/api').CreatePATResult | null} */
	let revealed = null;
	let copied = false;
	let revealAcknowledged = false;

	/** @type {import('$lib/api').PATInfo | null} */
	let revoking = null;
	let showRevokeConfirm = false;

	$: canIssue =
		issueName.trim().length > 0 &&
		(issueExpiryMode !== 'custom' || issueExpiresIn.trim().length > 0) &&
		!issuing;

	onMount(() => {
		load();
	});

	async function load() {
		loading = true;
		error = '';
		try {
			const listed = await listPATs();
			tokens = listed.tokens || [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load tokens';
			tokens = [];
		} finally {
			loading = false;
		}
	}

	function openIssue() {
		issueName = '';
		issueExpiryMode = 'default';
		issueExpiresIn = '';
		showIssueModal = true;
	}

	async function submitIssue() {
		if (!canIssue) return;
		issuing = true;
		try {
			/** @type {import('$lib/api').CreatePATInput} */
			const input = { name: issueName.trim() };
			if (issueExpiryMode === 'never') input.never_expires = true;
			if (issueExpiryMode === 'custom') input.expires_in = issueExpiresIn.trim();
			const created = await createPAT(input);
			showIssueModal = false;
			revealed = created;
			copied = false;
			revealAcknowledged = false;
			// Toast before reload — same order as API keys so UI feedback is not gated on list fetch.
			showToast(`Issued token "${created.name}"`, 'success');
			await load();
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to issue token', 'error');
		} finally {
			issuing = false;
		}
	}

	async function copyToken() {
		if (!revealed?.token) return;
		try {
			await navigator.clipboard.writeText(revealed.token);
			copied = true;
			showToast('Copied to clipboard', 'success');
		} catch {
			showToast('Could not copy', 'error');
		}
	}

	function closeReveal() {
		if (!revealAcknowledged) return;
		revealed = null;
		copied = false;
		revealAcknowledged = false;
	}

	function askRevoke(/** @type {import('$lib/api').PATInfo} */ token) {
		revoking = token;
		showRevokeConfirm = true;
	}

	async function confirmRevoke() {
		if (!revoking) return;
		const id = revoking.id;
		revoking = null;
		try {
			await revokePAT(id);
			showToast('Token revoked', 'success');
			await load();
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to revoke token', 'error');
		}
	}

	/** @param {string | null | undefined} iso */
	function formatWhen(iso) {
		if (!iso) return '—';
		return new Date(iso).toLocaleString();
	}
</script>

<svelte:head>
	<title>Access tokens | garde</title>
</svelte:head>

<div class="container-wide" data-testid="tokens-page">
	<div class="mb-4">
		<a href="/dashboard" class="btn-secondary inline-flex items-center gap-2" data-testid="tokens-back">
			<ArrowLeft size={16} /> Dashboard
		</a>
	</div>

	<div class="card space-y-4">
		<div class="flex flex-wrap items-start justify-between gap-3">
			<div>
				<h1 class="page-title">Access tokens</h1>
				<p class="section-subtitle mt-1">
					Personal tokens authenticate as you on garde APIs. They are not tenant
					<code class="text-xs">/validate</code> keys.
				</p>
			</div>
			<button type="button" class="btn-primary" data-testid="tokens-issue" on:click={openIssue}>
				<Plus size={16} class="inline mr-1" />
				Issue token
			</button>
		</div>

		{#if loading}
			<p class="text-muted" data-testid="tokens-loading">Loading...</p>
		{:else if error}
			<p class="text-error" data-testid="tokens-error">{error}</p>
		{:else if tokens.length === 0}
			<p class="text-muted py-6" data-testid="tokens-empty">
				No access tokens yet. Issue one for scripts or CI that need to call garde as you.
			</p>
		{:else}
			<div class="overflow-x-auto" data-testid="tokens-list">
				<table class="w-full text-sm">
					<thead>
						<tr class="text-left text-muted border-b border-border">
							<th class="px-3 py-2 font-medium">Name</th>
							<th class="px-3 py-2 font-medium">Created</th>
							<th class="px-3 py-2 font-medium">Expires</th>
							<th class="px-3 py-2 font-medium">Last used</th>
							<th class="px-3 py-2 font-medium"></th>
						</tr>
					</thead>
					<tbody>
						{#each tokens as token (token.id)}
							<tr class="border-b border-border/60" data-testid="tokens-row" data-token-id={token.id}>
								<td class="px-3 py-2 font-medium" data-testid="tokens-row-name">{token.name}</td>
								<td class="px-3 py-2 text-muted">{formatWhen(token.created_at)}</td>
								<td class="px-3 py-2 text-muted" data-testid="tokens-row-expires">
									{token.expires_at ? formatWhen(token.expires_at) : 'Never'}
								</td>
								<td class="px-3 py-2 text-muted">{formatWhen(token.last_used_at)}</td>
								<td class="px-3 py-2 text-right">
									<button
										type="button"
										class="btn-icon-danger"
										data-testid="tokens-revoke"
										title="Revoke token"
										on:click={() => askRevoke(token)}
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
</div>

<Modal
	bind:open={showIssueModal}
	title="Issue access token"
	labelledBy="tokens-issue-title"
	on:close={() => (showIssueModal = false)}
>
	<form class="space-y-4" data-testid="tokens-issue-modal" on:submit|preventDefault={submitIssue}>
		<div>
			<label class="form-label" for="tokens-issue-name">Name</label>
			<input
				id="tokens-issue-name"
				class="input w-full"
				data-testid="tokens-issue-name"
				placeholder="ci-laptop"
				autocomplete="off"
				bind:value={issueName}
			/>
		</div>
		<div>
			<p class="form-label">Expiry</p>
			<div class="flex flex-wrap gap-3 mt-1" data-testid="tokens-issue-expiry-mode">
				<label class="inline-flex items-center gap-2 text-sm">
					<input type="radio" name="pat-expiry" bind:group={issueExpiryMode} value="default" data-testid="tokens-issue-expiry-default" />
					90 days (default)
				</label>
				<label class="inline-flex items-center gap-2 text-sm">
					<input type="radio" name="pat-expiry" bind:group={issueExpiryMode} value="custom" data-testid="tokens-issue-expiry-custom" />
					Custom
				</label>
				<label class="inline-flex items-center gap-2 text-sm">
					<input type="radio" name="pat-expiry" bind:group={issueExpiryMode} value="never" data-testid="tokens-issue-expiry-never" />
					Never
				</label>
			</div>
			{#if issueExpiryMode === 'custom'}
				<input
					class="input w-full mt-2"
					data-testid="tokens-issue-expires-in"
					placeholder="720h"
					bind:value={issueExpiresIn}
				/>
			{/if}
		</div>
		<div class="flex justify-end gap-2">
			<button
				type="button"
				class="btn-secondary"
				data-testid="tokens-issue-cancel"
				on:click={() => {
					// Defer unmount so Playwright's click can finish (same class of hang as ConfirmModal).
					queueMicrotask(() => {
						showIssueModal = false;
					});
				}}
			>
				Cancel
			</button>
			<button type="submit" class="btn-primary" data-testid="tokens-issue-submit" disabled={!canIssue}>
				{issuing ? 'Issuing…' : 'Issue'}
			</button>
		</div>
	</form>
</Modal>

<Modal
	open={!!revealed}
	title="Copy your token"
	labelledBy="tokens-reveal-title"
	dismissible={false}
	on:close={closeReveal}
>
	{#if revealed}
		<div class="space-y-4" data-testid="tokens-reveal-modal">
			<p class="text-sm text-error font-medium" data-testid="tokens-reveal-warning">
				This token is shown once. Store it now — garde cannot show it again.
			</p>
			<p class="text-sm text-muted flex items-center gap-2">
				<KeyRound size={16} /> {revealed.name}
			</p>
			<div class="flex gap-2 items-start">
				<code class="input flex-1 break-all text-xs" data-testid="tokens-reveal-secret">{revealed.token}</code>
				<button type="button" class="btn-secondary shrink-0" data-testid="tokens-reveal-copy" on:click={copyToken}>
					{#if copied}<Check size={16} />{:else}<Copy size={16} />{/if}
				</button>
			</div>
			<label class="inline-flex items-start gap-2 text-sm" data-testid="tokens-reveal-ack-label">
				<input type="checkbox" data-testid="tokens-reveal-ack" bind:checked={revealAcknowledged} />
				I have stored this token and understand it cannot be recovered.
			</label>
			<div class="flex justify-end">
				<button
					type="button"
					class="btn-primary"
					data-testid="tokens-reveal-done"
					disabled={!revealAcknowledged}
					on:click={closeReveal}
				>
					Done
				</button>
			</div>
		</div>
	{/if}
</Modal>

<ConfirmModal
	bind:open={showRevokeConfirm}
	title="Revoke access token"
	message={revoking
		? `Revoke "${revoking.name}" (${revoking.id})?\n\nAnything using this token will be refused immediately.`
		: ''}
	confirmText="Revoke"
	on:confirm={confirmRevoke}
	on:cancel={() => {
		showRevokeConfirm = false;
		revoking = null;
	}}
/>
