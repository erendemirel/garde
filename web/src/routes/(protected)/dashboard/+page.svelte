<script>
	import { onMount } from 'svelte';
	import { user, isSuperuser } from '$lib/stores';
	import { refreshSession } from '$lib/session';
	import { ShieldCheck, KeyRound, MailQuestion } from 'lucide-svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import MfaLabel from '$lib/components/MfaLabel.svelte';

	const hasEnabled = (record) => Object.values(record || {}).some(Boolean);

	onMount(() => {
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
					<p class="info-value">{$user.last_login ? new Date($user.last_login).toLocaleString() : 'Never'}</p>
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
								<span class="badge badge-permission" data-testid="dashboard-permission-chip" data-key={perm}>
									{perm}
								</span>
							{/if}
						{/each}
					</div>
				{:else}
					<p class="text-sm text-muted" data-testid="dashboard-permissions-empty">No permissions assigned.</p>
				{/if}
			</div>

			<div class="pill-card space-y-3" data-testid="dashboard-groups">
				<h2 class="section-title">Groups</h2>
				{#if hasEnabled($user.groups)}
					<div class="chip-row">
						{#each Object.entries($user.groups) as [group, member]}
							{#if member}
								<span class="badge badge-group" data-testid="dashboard-group-chip" data-key={group}>{group}</span>
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
					<p class="text-sm text-muted">
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

			<div class="actions">
				<a href="/mfa" class="btn-secondary" data-testid="dashboard-link-mfa"
					><ShieldCheck size={18} />{$user.mfa_enabled ? 'Manage MFA' : 'Setup MFA'}</a
				>
				<a href="/password" class="btn-secondary" data-testid="dashboard-link-password"
					><KeyRound size={18} />Change Password</a
				>
				{#if !$isSuperuser}
					<a href="/request-update" class="btn-secondary" data-testid="dashboard-link-request-update"
						><MailQuestion size={18} />Request Update</a
					>
				{/if}
			</div>
		{/if}
	</div>
</div>
