<script>
	import { afterNavigate } from '$app/navigation';
	import { user, isSuperuser } from '$lib/stores';
	import { refreshSession } from '$lib/session';
	import {
		ShieldCheck,
		KeyRound,
		MailQuestion,
		UserKey,
		Monitor,
		ChevronRight
	} from '@lucide/svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import MfaLabel from '$lib/components/MfaLabel.svelte';

	/** @param {Record<string, boolean> | null | undefined} record */
	const hasEnabled = (record) => Object.values(record || {}).some(Boolean);

	/** Public auth routes already hand off into a layout that just called refreshSession. */
	const PUBLIC_FROM = new Set(['/', '/register', '/forgot-password', '/verify-email']);

	afterNavigate(({ from }) => {
		// Skip first paint / login handoff — (protected)/+layout already refreshed.
		if (!from || PUBLIC_FROM.has(from.url.pathname)) return;
		void refreshSession().catch(() => undefined);
	});
</script>

<svelte:head>
	<title>Dashboard | garde</title>
</svelte:head>

<div class="container-wide" data-testid="dashboard-page">
	<div class="card space-y-4">
		<div class="flex items-start justify-between gap-3">
			<div>
				<h1 class="page-title">Dashboard</h1>
				<p class="section-subtitle">Your account overview</p>
			</div>
		</div>

		{#if $user}
			<div class="info-grid">
				<div class="info-card">
					<p class="info-label">Email</p>
					<p class="info-value" data-testid="dashboard-email">{$user.email}</p>
				</div>
				<div class="info-card">
					<p class="info-label">Status</p>
					<p class="info-value" data-testid="dashboard-status">
						<StatusBadge status={$user.status} />
					</p>
				</div>
				<div class="info-card">
					<p class="info-label">MFA</p>
					<p class="info-value" data-testid="dashboard-mfa">
						<MfaLabel enabled={$user.mfa_enabled} enforced={$user.mfa_enforced} />
					</p>
				</div>
				<div class="info-card">
					<p class="info-label">Last Login</p>
					<p class="info-value"
						>{$user.last_login ? new Date($user.last_login).toLocaleString() : 'Never'}</p
					>
				</div>
				<div class="info-card">
					<p class="info-label">Created</p>
					<p class="info-value">{new Date($user.created_at).toLocaleDateString()}</p>
				</div>
			</div>

			<div class="pill-card space-y-3" data-testid="dashboard-permissions">
				<h2 class="section-title">Permissions</h2>
				{#if hasEnabled($user.permissions)}
					<div class="chip-row">
						{#each Object.entries($user.permissions) as [perm, enabled]}
							{#if enabled}
								<span
									class="badge badge-permission"
									data-testid="dashboard-permission-chip"
									data-key={perm}
								>
									{perm}
								</span>
							{/if}
						{/each}
					</div>
				{:else}
					<p class="text-sm text-muted" data-testid="dashboard-permissions-empty"
						>No permissions assigned.</p
					>
				{/if}
			</div>

			<div class="pill-card space-y-3" data-testid="dashboard-groups">
				<h2 class="section-title">Groups</h2>
				{#if hasEnabled($user.groups)}
					<div class="chip-row">
						{#each Object.entries($user.groups) as [group, member]}
							{#if member}
								<span
									class="badge badge-group"
									data-testid="dashboard-group-chip"
									data-key={group}>{group}</span
								>
							{/if}
						{/each}
					</div>
				{:else}
					<p class="text-sm text-muted" data-testid="dashboard-groups-empty">No groups assigned.</p>
				{/if}
			</div>

			{#if $user.pending_updates}
				{@const fields = $user.pending_updates.fields || {}}
				<div class="pill-card border-warning/40 space-y-3" data-testid="dashboard-pending-update">
					<h2 class="section-title text-warning">Pending Update Request</h2>
					<p class="section-subtitle">
						Submitted: {new Date($user.pending_updates.requested_at).toLocaleString()}
					</p>
					{#if fields.permissions_add?.length || fields.permissions_remove?.length}
						<div class="space-y-2">
							<p class="text-sm font-semibold text-text">Permissions</p>
							<div class="flex flex-wrap gap-2">
								{#each fields.permissions_add || [] as perm}
									<span class="badge badge-permission">Add: {perm}</span>
								{/each}
								{#each fields.permissions_remove || [] as perm}
									<span class="badge badge-locked">Remove: {perm}</span>
								{/each}
							</div>
						</div>
					{/if}
					{#if fields.groups_add?.length || fields.groups_remove?.length}
						<div class="space-y-2">
							<p class="text-sm font-semibold text-text">Groups</p>
							<div class="flex flex-wrap gap-2">
								{#each fields.groups_add || [] as group}
									<span class="badge badge-group">Join: {group}</span>
								{/each}
								{#each fields.groups_remove || [] as group}
									<span class="badge badge-locked">Leave: {group}</span>
								{/each}
							</div>
						</div>
					{/if}
				</div>
			{/if}

			<div class="space-y-3" data-testid="dashboard-account-security">
				<div>
					<h2 class="section-title">Account security</h2>
					<p class="section-subtitle">Manage how you sign in and what can access your account</p>
				</div>
				<div class="settings-list">
					<a href="/mfa" class="settings-row" data-testid="dashboard-link-mfa">
						<span class="settings-row-icon"><ShieldCheck size={20} /></span>
						<span class="settings-row-body">
							<span class="settings-row-title"
								>{$user.mfa_enabled ? 'Manage MFA' : 'Setup MFA'}</span
							>
							<span class="settings-row-desc">Set up or manage authenticator</span>
						</span>
						<span class="settings-row-chevron" aria-hidden="true"
							><ChevronRight size={18} /></span
						>
					</a>
					<a href="/password" class="settings-row" data-testid="dashboard-link-password">
						<span class="settings-row-icon"><UserKey size={20} /></span>
						<span class="settings-row-body">
							<span class="settings-row-title">Change password</span>
							<span class="settings-row-desc">Update your sign-in password</span>
						</span>
						<span class="settings-row-chevron" aria-hidden="true"
							><ChevronRight size={18} /></span
						>
					</a>
					<a href="/tokens" class="settings-row" data-testid="dashboard-link-tokens">
						<span class="settings-row-icon"><KeyRound size={20} /></span>
						<span class="settings-row-body">
							<span class="settings-row-title">Access tokens</span>
							<span class="settings-row-desc">Personal tokens for APIs and CI</span>
						</span>
						<span class="settings-row-chevron" aria-hidden="true"
							><ChevronRight size={18} /></span
						>
					</a>
					<a href="/sessions" class="settings-row" data-testid="dashboard-link-sessions">
						<span class="settings-row-icon"><Monitor size={20} /></span>
						<span class="settings-row-body">
							<span class="settings-row-title">Active sessions</span>
							<span class="settings-row-desc">Devices signed into your account</span>
						</span>
						<span class="settings-row-chevron" aria-hidden="true"
							><ChevronRight size={18} /></span
						>
					</a>
				</div>
			</div>

			{#if !$isSuperuser}
				<div class="space-y-3" data-testid="dashboard-access">
					<div>
						<h2 class="section-title">Access</h2>
						<p class="section-subtitle">Ask an admin to change your permissions or groups</p>
					</div>
					<div class="settings-list">
						<a
							href="/request-update"
							class="settings-row"
							data-testid="dashboard-link-request-update"
						>
							<span class="settings-row-icon"><MailQuestion size={20} /></span>
							<span class="settings-row-body">
								<span class="settings-row-title">Request update</span>
								<span class="settings-row-desc">Request permission or group changes</span>
							</span>
							<span class="settings-row-chevron" aria-hidden="true"
								><ChevronRight size={18} /></span
							>
						</a>
					</div>
				</div>
			{/if}
		{/if}
	</div>
</div>
