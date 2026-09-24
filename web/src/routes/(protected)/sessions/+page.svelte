<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { listSessions, revokeSession, revokeOtherSessions } from '$lib/api';
	import { showToast } from '$lib/toast';
	import { user } from '$lib/stores';
	import {
		ArrowLeft,
		Trash2,
		LogOut,
		MonitorPc,
		Smartphone,
		CircleQuestionMark,
		FileCog
	} from '@lucide/svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';

	/** @type {import('$lib/api').SessionInfo[]} */
	let sessions = $state([]);
	let loading = $state(true);
	let error = $state('');

	/** @type {'last_seen_at' | 'created_at'} */
	let sortField = $state('last_seen_at');
	/** @type {'asc' | 'desc'} */
	let sortDirection = $state('desc');

	/** @type {import('$lib/api').SessionInfo | null} */
	let revoking = $state(null);
	let showRevokeOne = $state(false);
	let showRevokeOthers = $state(false);
	let mfaCode = $state('');
	let busy = $state(false);

	let needsMfa = $derived(!!$user?.mfa_enabled);
	let othersCount = $derived(sessions.filter((s) => !s.current).length);

	let sortedSessions = $derived.by(() => {
		const rows = [...sessions];
		const dir = sortDirection === 'asc' ? 1 : -1;
		const key = sortField;
		rows.sort((a, b) => {
			const ta = new Date(a[key] || 0).getTime();
			const tb = new Date(b[key] || 0).getTime();
			if (ta === tb) return 0;
			return ta < tb ? -dir : dir;
		});
		return rows;
	});

	onMount(() => {
		load();
	});

	async function load() {
		loading = true;
		error = '';
		try {
			const listed = await listSessions();
			sessions = listed.sessions || [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load sessions';
			sessions = [];
		} finally {
			loading = false;
		}
	}

	/** @param {'last_seen_at' | 'created_at'} field */
	function handleSort(field) {
		if (sortField === field) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			sortField = field;
			sortDirection = 'desc';
		}
	}

	/** @param {'last_seen_at' | 'created_at'} field */
	function sortAria(field) {
		if (sortField !== field) return 'none';
		return sortDirection === 'asc' ? 'ascending' : 'descending';
	}

	/** @param {import('$lib/api').SessionInfo} s */
	function deviceKind(s) {
		const k = (s.device_kind || '').toLowerCase();
		if (k === 'desktop' || k === 'mobile' || k === 'tool' || k === 'unknown') return k;
		const family = (s.ua_family || '').toLowerCase();
		if (family === 'curl' || family === 'postman' || family === 'script') return 'tool';
		const summary = (s.ua_summary || '').toLowerCase();
		if (summary.includes('android') || summary.includes('ios')) return 'mobile';
		if (summary.includes('unknown')) return 'unknown';
		if (summary.includes('windows') || summary.includes('macos') || summary.includes('linux')) {
			return 'desktop';
		}
		return 'unknown';
	}

	/** @param {string | null | undefined} iso */
	function formatWhen(iso) {
		if (!iso) return '—';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	function askRevokeOne(/** @type {import('$lib/api').SessionInfo} */ s) {
		revoking = s;
		mfaCode = '';
		showRevokeOne = true;
	}

	function askRevokeOthers() {
		mfaCode = '';
		showRevokeOthers = true;
	}

	async function confirmRevokeOne() {
		if (!revoking || busy) return;
		if (needsMfa && !revoking.current && !mfaCode.trim()) {
			showToast('Enter your MFA code', 'error');
			return;
		}
		busy = true;
		const target = revoking;
		try {
			const res = await revokeSession(
				target.id,
				needsMfa && !target.current ? mfaCode.trim() : undefined
			);
			showRevokeOne = false;
			revoking = null;
			mfaCode = '';
			if (res.revoked_current) {
				showToast('This session was signed out', 'success');
				await goto('/');
				return;
			}
			showToast('Session revoked', 'success');
			await load();
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to revoke session', 'error');
		} finally {
			busy = false;
		}
	}

	async function confirmRevokeOthers() {
		if (busy) return;
		if (needsMfa && !mfaCode.trim()) {
			showToast('Enter your MFA code', 'error');
			return;
		}
		busy = true;
		try {
			const res = await revokeOtherSessions(needsMfa ? mfaCode.trim() : undefined);
			showRevokeOthers = false;
			mfaCode = '';
			showToast(
				res.revoked === 1 ? 'Revoked 1 other session' : `Revoked ${res.revoked} other sessions`,
				'success'
			);
			await load();
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to revoke sessions', 'error');
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>Sessions | garde</title>
</svelte:head>

<div class="container-wide" data-testid="sessions-page">
	<div class="mb-4">
		<a
			href="/dashboard"
			class="btn-secondary inline-flex items-center gap-2"
			data-testid="sessions-back"
		>
			<ArrowLeft size={16} /> Dashboard
		</a>
	</div>

	<div class="card space-y-4">
		<div class="flex flex-wrap items-start justify-between gap-3">
			<div>
				<h1 class="page-title">Active sessions</h1>
				<p class="section-subtitle">
					Devices signed into your account. Location is a coarse network hint (masked IP), not a city.
				</p>
			</div>
			{#if othersCount > 0}
				<button
					type="button"
					class="btn-primary"
					data-testid="sessions-revoke-others"
					onclick={askRevokeOthers}
				>
					<Trash2 size={16} class="inline mr-1" />Sign out other sessions
				</button>
			{/if}
		</div>

		{#if loading}
			<p class="text-muted" data-testid="sessions-loading">Loading...</p>
		{:else if error}
			<p class="error" data-testid="sessions-error">{error}</p>
		{:else if sessions.length === 0}
			<p class="text-muted" data-testid="sessions-empty">No active sessions.</p>
		{:else}
			<div class="table-scroll" data-testid="sessions-list">
				<table class="table-base">
					<thead>
						<tr>
							<th>Device</th>
							<th>Location</th>
							<th aria-sort={sortAria('last_seen_at')}>
								<button
									type="button"
									class="flex items-center gap-1 hover:text-accent transition-colors"
									data-testid="sessions-sort-last-seen"
									data-sort-active={sortField === 'last_seen_at' ? 'true' : 'false'}
									data-sort-direction={sortField === 'last_seen_at' ? sortDirection : ''}
									onclick={() => handleSort('last_seen_at')}
								>
									Last seen
									{#if sortField === 'last_seen_at'}
										<span class="text-xs" aria-hidden="true"
											>{sortDirection === 'asc' ? '↑' : '↓'}</span
										>
									{/if}
								</button>
							</th>
							<th aria-sort={sortAria('created_at')}>
								<button
									type="button"
									class="flex items-center gap-1 hover:text-accent transition-colors"
									data-testid="sessions-sort-signed-in"
									data-sort-active={sortField === 'created_at' ? 'true' : 'false'}
									data-sort-direction={sortField === 'created_at' ? sortDirection : ''}
									onclick={() => handleSort('created_at')}
								>
									Signed in
									{#if sortField === 'created_at'}
										<span class="text-xs" aria-hidden="true"
											>{sortDirection === 'asc' ? '↑' : '↓'}</span
										>
									{/if}
								</button>
							</th>
							<th class="table-actions">Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each sortedSessions as s (s.id)}
							{@const kind = deviceKind(s)}
							<tr
								data-testid="sessions-row"
								data-current={s.current ? 'true' : 'false'}
								data-session-id={s.id}
								data-device-kind={kind}
							>
								<td>
									<span class="inline-flex items-center gap-2 font-semibold text-text">
										<span
											class="text-muted shrink-0"
											data-testid="sessions-row-device-icon"
											aria-hidden="true"
										>
											{#if kind === 'mobile'}
												<Smartphone size={18} />
											{:else if kind === 'tool'}
												<FileCog size={18} />
											{:else if kind === 'desktop'}
												<MonitorPc size={18} />
											{:else}
												<CircleQuestionMark size={18} />
											{/if}
										</span>
										<span data-testid="sessions-row-summary"
											>{s.ua_summary || s.ua_family || 'Session'}</span
										>
										{#if s.current}
											<span class="badge badge-permission" data-testid="sessions-row-current"
												>This device</span
											>
										{/if}
									</span>
								</td>
								<td data-testid="sessions-row-place">{s.approx_place || s.ip_display || 'unknown'}</td>
								<td class="whitespace-nowrap">{formatWhen(s.last_seen_at)}</td>
								<td class="whitespace-nowrap">{formatWhen(s.created_at)}</td>
								<td class="table-actions">
									<button
										type="button"
										class="inline-flex items-center gap-1.5 rounded-md border-0 bg-transparent px-1 py-1 text-sm font-semibold text-accent shadow-none transition-colors duration-150 ease-out hover:bg-accent/10 hover:text-accent"
										data-testid="sessions-row-revoke"
										onclick={() => askRevokeOne(s)}
									>
										{#if s.current}
											<LogOut size={16} />Sign out
										{:else}
											<Trash2 size={16} />Revoke
										{/if}
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

{#if needsMfa && revoking && !revoking.current}
	<Modal
		bind:open={showRevokeOne}
		title="Revoke this session?"
		onClose={() => {
			showRevokeOne = false;
			revoking = null;
			mfaCode = '';
		}}
	>
		<p class="text-text mb-4 whitespace-pre-line" data-testid="confirm-modal-message">
			Revoke {revoking.ua_summary || 'this session'} ({revoking.approx_place || 'unknown'})? Enter your
			MFA code to confirm.
		</p>
		<label class="flex flex-col gap-2 text-sm font-semibold text-muted mb-6">
			MFA code
			<input
				class="input"
				type="text"
				inputmode="numeric"
				autocomplete="one-time-code"
				bind:value={mfaCode}
				data-testid="sessions-revoke-mfa"
				placeholder="6-digit code"
			/>
		</label>
		<div class="modal-actions">
			<button
				type="button"
				class="btn-secondary"
				data-testid="confirm-modal-cancel"
				onclick={() => {
					showRevokeOne = false;
					revoking = null;
					mfaCode = '';
				}}>Cancel</button
			>
			<button
				type="button"
				class="btn-danger"
				data-testid="confirm-modal-confirm"
				onclick={confirmRevokeOne}>Revoke</button
			>
		</div>
	</Modal>
{:else}
	<ConfirmModal
		bind:open={showRevokeOne}
		title={revoking?.current ? 'Sign out this device?' : 'Revoke this session?'}
		message={revoking?.current
			? 'You will need to sign in again on this browser.'
			: `Revoke ${revoking?.ua_summary || 'this session'} (${revoking?.approx_place || 'unknown'})?`}
		confirmText={revoking?.current ? 'Sign out' : 'Revoke'}
		confirmClass="btn-danger"
		onConfirm={confirmRevokeOne}
		onCancel={() => {
			revoking = null;
			mfaCode = '';
		}}
	/>
{/if}

{#if needsMfa}
	<Modal
		bind:open={showRevokeOthers}
		title="Sign out other sessions?"
		onClose={() => {
			showRevokeOthers = false;
			mfaCode = '';
		}}
	>
		<p class="text-text mb-4 whitespace-pre-line" data-testid="confirm-modal-message">
			All sessions except this device will be revoked. Enter your MFA code to confirm.
		</p>
		<label class="flex flex-col gap-2 text-sm font-semibold text-muted mb-6">
			MFA code
			<input
				class="input"
				type="text"
				inputmode="numeric"
				autocomplete="one-time-code"
				bind:value={mfaCode}
				data-testid="sessions-revoke-others-mfa"
				placeholder="6-digit code"
			/>
		</label>
		<div class="modal-actions">
			<button
				type="button"
				class="btn-secondary"
				data-testid="confirm-modal-cancel"
				onclick={() => {
					showRevokeOthers = false;
					mfaCode = '';
				}}>Cancel</button
			>
			<button
				type="button"
				class="btn-danger"
				data-testid="confirm-modal-confirm"
				onclick={confirmRevokeOthers}>Sign out others</button
			>
		</div>
	</Modal>
{:else}
	<ConfirmModal
		bind:open={showRevokeOthers}
		title="Sign out other sessions?"
		message="All sessions except this device will be revoked immediately."
		confirmText="Sign out others"
		confirmClass="btn-danger"
		onConfirm={confirmRevokeOthers}
		onCancel={() => {
			mfaCode = '';
		}}
	/>
{/if}
