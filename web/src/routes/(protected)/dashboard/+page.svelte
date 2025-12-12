<script>
	import { user, isSuperuser } from '$lib/stores';
	import { CircleCheck, CircleX, CircleAlert, ShieldCheck, KeyRound, MailQuestion } from 'lucide-svelte';

	function getStatusClass(status) {
		if (status === 'ok') return 'ok';
		if (status.toLowerCase().includes('locked') || status.toLowerCase().includes('disabled')) return 'locked';
		if (status.toLowerCase().includes('pending')) return 'pending';
		return 'pending';
	}

const hasEnabled = (record) => Object.values(record || {}).some(Boolean);
</script>

<svelte:head>
	<title>Dashboard | garde</title>
</svelte:head>

<div class="container-wide">
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
					<p class="info-value">{$user.email}</p>
				</div>
				<div class="info-card">
					<p class="info-label">Status</p>
					<p class="info-value">
						<span class="status-display status-{getStatusClass($user.status)}">
							<span class="status-icon">
								{#if getStatusClass($user.status) === 'ok'}
									<CircleCheck size={18} />
								{:else if getStatusClass($user.status) === 'locked'}
									<CircleX size={18} />
								{:else}
									<CircleAlert size={18} />
								{/if}
							</span>
							<span class="status-text">{$user.status}</span>
						</span>
					</p>
				</div>
				<div class="info-card">
					<p class="info-label">MFA</p>
					<p class="info-value">
						{$user.mfa_enabled ? 'Enabled' : 'Disabled'}
						{$user.mfa_enforced ? '(Enforced)' : ''}
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

			<div class="pill-card space-y-3">
				<h2 class="section-title">Permissions</h2>
				{#if hasEnabled($user.permissions)}
					<div class="chip-group">
						{#each Object.entries($user.permissions) as [perm, enabled]}
							{#if enabled}
								<span class="badge badge-permission">
									{perm}
								</span>
							{/if}
						{/each}
					</div>
				{:else}
					<p class="text-sm text-muted">No permissions assigned.</p>
				{/if}
			</div>

			<div class="pill-card space-y-3">
				<h2 class="section-title">Groups</h2>
				{#if hasEnabled($user.groups)}
					<div class="chip-group">
						{#each Object.entries($user.groups) as [group, member]}
							{#if member}
								<span class="badge badge-group">{group}</span>
							{/if}
						{/each}
					</div>
				{:else}
					<p class="text-sm text-muted">No groups assigned.</p>
				{/if}
			</div>

			{#if $user.pending_updates}
				<div class="pill-card border-warning/40">
					<h2 class="section-title text-warning">Pending Update Request</h2>
					<p class="text-sm text-muted">
						Submitted: {new Date($user.pending_updates.requested_at).toLocaleString()}
					</p>
				</div>
			{/if}

			<div class="actions">
				<a href="/mfa"><button class="btn-secondary"><ShieldCheck size={18} />{$user.mfa_enabled ? 'Manage MFA' : 'Setup MFA'}</button></a>
				<a href="/password"><button class="btn-secondary"><KeyRound size={18} />Change Password</button></a>
				{#if !$isSuperuser}
					<a href="/request-update"><button class="btn-secondary"><MailQuestion size={18} />Request Update</button></a>
				{/if}
			</div>
		{/if}
	</div>
</div>

