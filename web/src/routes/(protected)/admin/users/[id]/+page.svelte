<script>
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { getUser, updateUser, revokeSessions, deleteUser, listPermissions, listGroups } from '$lib/api';
	import { user as currentUser } from '$lib/stores';
	import { CircleCheck, CircleX, CircleAlert, Save, ArrowLeft, Check, X, LogOut, Send, Trash2 } from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	let userData = null;
	let error = '';
	let success = '';
	let loading = true;
	let saving = false;
	let accessDenied = false;
	let showToast = false;
	let toastMessage = '';
	let toastType = 'success';
	let showDeleteConfirm = false;

	// Edit fields
	let status = '';
	let mfaEnforced = false;
	let mfaCode = '';

	// Available permissions and groups from config
	let availablePermissions = [];
	let availableGroups = [];
	
	// Editable permissions and groups
	let editPermissions = {};
	let editGroups = {};
	
	// Search filters
	let permissionSearch = '';
	let groupSearch = '';

	$: userId = $page.params.id;
$: hasEnabledPermissions = Object.values(userData?.permissions || {}).some(Boolean);

	onMount(async () => {
		try {
			// Load available permissions and groups
			const [perms, grps, user] = await Promise.all([
				listPermissions().catch(() => []),
				listGroups().catch(() => []),
				getUser(userId)
			]);
			
			availablePermissions = perms || [];
			availableGroups = grps || [];
			userData = user;
			status = userData.status;
			mfaEnforced = userData.mfa_enforced;
			
			// Initialize edit states from current user data
			editPermissions = { ...(userData.permissions || {}) };
			editGroups = { ...(userData.groups || {}) };
		} catch (e) {
			const msg = e instanceof Error ? e.message : '';
			if (msg.toLowerCase().includes('unauthorized') || msg.toLowerCase().includes('forbidden') || msg.toLowerCase().includes('permission')) {
				accessDenied = true;
			} else {
				error = msg || 'Failed to load user';
			}
		}
		loading = false;
	});

	function showToastMessage(message, type = 'success') {
		toastMessage = message;
		toastType = type;
		showToast = true;
		setTimeout(() => {
			showToast = false;
		}, 3000);
	}

	async function handleUpdate() {
		saving = true;
		try {
			const updatedUser = await updateUser(userId, {
				status,
				mfa_enforced: mfaEnforced,
				permissions: editPermissions,
				groups: editGroups
			});
			showToastMessage('User updated!', 'success');
			if (updatedUser) {
				userData = updatedUser;
				// Refresh edit states
				status = userData.status;
				mfaEnforced = userData.mfa_enforced;
				editPermissions = { ...(userData.permissions || {}) };
				editGroups = { ...(userData.groups || {}) };
			} else {
				// Fallback to fetching if response is null
			userData = await getUser(userId);
				if (userData) {
					status = userData.status;
					mfaEnforced = userData.mfa_enforced;
			editPermissions = { ...(userData.permissions || {}) };
			editGroups = { ...(userData.groups || {}) };
				}
			}
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Update failed', 'error');
		}
		saving = false;
	}

	async function handleApproveUpdate() {
		saving = true;
		try {
			const updatedUser = await updateUser(userId, { approve_update: true });
			showToastMessage('Update approved!', 'success');
			if (updatedUser) {
				userData = updatedUser;
				// Refresh form state
				status = userData.status;
				mfaEnforced = userData.mfa_enforced;
				editPermissions = { ...(userData.permissions || {}) };
				editGroups = { ...(userData.groups || {}) };
			} else {
				// Fallback to fetching if response is null
			userData = await getUser(userId);
				if (userData) {
					status = userData.status;
					mfaEnforced = userData.mfa_enforced;
					editPermissions = { ...(userData.permissions || {}) };
					editGroups = { ...(userData.groups || {}) };
				}
			}
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Approval failed', 'error');
		}
		saving = false;
	}

	async function handleRejectUpdate() {
		saving = true;
		try {
			const updatedUser = await updateUser(userId, { reject_update: true });
			showToastMessage('Update rejected!', 'success');
			if (updatedUser) {
				userData = updatedUser;
				// Refresh form state
				status = userData.status;
				mfaEnforced = userData.mfa_enforced;
				editPermissions = { ...(userData.permissions || {}) };
				editGroups = { ...(userData.groups || {}) };
			} else {
				// Fallback to fetching if response is null
			userData = await getUser(userId);
				if (userData) {
					status = userData.status;
					mfaEnforced = userData.mfa_enforced;
					editPermissions = { ...(userData.permissions || {}) };
					editGroups = { ...(userData.groups || {}) };
				}
			}
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Rejection failed', 'error');
		}
		saving = false;
	}

	async function handleRevokeSessions() {
		saving = true;
		try {
			await revokeSessions(userId, $currentUser?.mfa_enabled ? mfaCode : undefined);
			showToastMessage('Sessions revoked!', 'success');
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Failed to revoke sessions', 'error');
		}
		saving = false;
	}

	function requestDeleteConfirmation() {
		showDeleteConfirm = true;
	}

	async function handleDelete() {
		saving = true;
		showDeleteConfirm = false;
		try {
			await deleteUser(userId);
			showToastMessage('User deleted successfully!', 'success');
			// Navigate to admin page after a short delay
			setTimeout(() => {
				goto('/admin');
			}, 1500);
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Failed to delete user', 'error');
			saving = false;
		}
	}

	function getStatusClass(s) {
		const v = s.toLowerCase();
		if (v === 'ok') return 'ok';
		if (v.includes('locked') || v.includes('disabled')) return 'locked';
		if (v.includes('pending')) return 'pending';
		return 'pending';
	}
</script>

<svelte:head>
	<title>User Details | garde</title>
</svelte:head>

<div class="container-medium">
	<div class="card space-y-4">
		{#if loading}
			<p class="text-muted">Loading...</p>
		{:else if accessDenied}
			<h1 class="page-title text-error">Access Denied</h1>
			<p class="text-muted mb-4">
				You don't have permission to view this user. Admin privileges are required.
			</p>
			<a href="/dashboard"><button class="btn-secondary"><ArrowLeft size={18} />Back to Dashboard</button></a>
		{:else if error && !userData}
			<p class="error">{error}</p>
			<div class="links">
				<a href="/admin">Back to users</a>
			</div>
		{:else if userData}
			<div class="flex items-start justify-between gap-3">
				<div>
					<h1 class="page-title">User Details</h1>
					<p class="section-subtitle">Review and edit user access</p>
				</div>
				<a href="/admin" class="w-full sm:w-auto sm:ml-auto">
					<button class="btn-secondary w-full sm:w-auto"><ArrowLeft size={18} />Back to users</button>
				</a>
			</div>

			<div class="info-grid">
				<div class="info-card">
					<p class="info-label">ID</p>
					<p class="info-value monospace text-[13px]">{userData.id}</p>
				</div>
				<div class="info-card">
					<p class="info-label">Email</p>
					<p class="info-value">{userData.email}</p>
				</div>
				<div class="info-card">
					<p class="info-label">Status</p>
					<p class="info-value">
						<span class="status-display status-{getStatusClass(userData.status)}">
							<span class="status-icon">
								{#if getStatusClass(userData.status) === 'ok'}
									<CircleCheck size={18} />
								{:else if getStatusClass(userData.status) === 'locked'}
									<CircleX size={18} />
								{:else}
									<CircleAlert size={18} />
								{/if}
							</span>
							<span class="status-text">{userData.status}</span>
						</span>
					</p>
				</div>
				<div class="info-card">
					<p class="info-label">MFA</p>
					<p class="info-value">
						{userData.mfa_enabled ? 'Enabled' : 'Disabled'}
						{userData.mfa_enforced ? ' (Enforced)' : ''}
					</p>
				</div>
				<div class="info-card">
					<p class="info-label">Created</p>
					<p class="info-value">{new Date(userData.created_at).toLocaleString()}</p>
				</div>
				<div class="info-card">
					<p class="info-label">Last Login</p>
					<p class="info-value">{userData.last_login ? new Date(userData.last_login).toLocaleString() : 'Never'}</p>
				</div>
			</div>

				<h2>Current Permissions</h2>
			{#if hasEnabledPermissions}
				<div class="chip-group mb-3">
					{#each Object.entries(userData.permissions || {}) as [perm, enabled]}
						{#if enabled}
							<span class="badge badge-permission">
								{perm}
							</span>
						{/if}
					{/each}
				</div>
			{:else}
				<p class="text-sm text-muted mb-3">No permissions assigned.</p>
			{/if}

			<h2>Current Groups</h2>
			{#if Object.keys(userData.groups || {}).length > 0}
				<div class="chip-group mb-3">
					{#each Object.entries(userData.groups) as [group, member]}
						{#if member}
							<span class="badge badge-group">{group}</span>
						{/if}
					{/each}
				</div>
			{:else}
				<p class="text-sm text-muted mb-3">No groups assigned.</p>
			{/if}

			{#if userData.pending_updates}
				{@const fields = userData.pending_updates.fields || {}}
				
				{@const permissionChanges = (() => {
					const changes = [];
					if (fields.permissions_add) {
						fields.permissions_add.forEach(perm => changes.push({ perm, isAdd: true }));
					}
					if (fields.permissions_remove) {
						fields.permissions_remove.forEach(perm => changes.push({ perm, isAdd: false }));
					}
					return changes;
				})()}
				
				{@const groupChanges = (() => {
					const changes = [];
					if (fields.groups_add) {
						fields.groups_add.forEach(group => changes.push({ group, isAdd: true }));
					}
					if (fields.groups_remove) {
						fields.groups_remove.forEach(group => changes.push({ group, isAdd: false }));
					}
					return changes;
				})()}
				
				<div class="card-muted space-y-4 my-6">
					<h2 class="section-title text-warning">Pending Update Request</h2>
					<p class="text-xs text-muted">
						Requested: {new Date(userData.pending_updates.requested_at).toLocaleString()}
					</p>
					
					{#if permissionChanges.length > 0}
						<div class="space-y-3">
						<p class="text-sm font-semibold text-text">Permissions:</p>
							<div class="flex flex-wrap gap-2">
								{#each permissionChanges as { perm, isAdd }}
									<span class="badge {isAdd ? 'badge-permission' : 'badge-locked'}">
										{isAdd ? '➕ Add' : '➖ Remove'}: {perm}
									</span>
							{/each}
							</div>
						</div>
					{/if}
					
					{#if groupChanges.length > 0}
						<div class="space-y-3">
						<p class="text-sm font-semibold text-text">Groups:</p>
							<div class="flex flex-wrap gap-2">
								{#each groupChanges as { group, isAdd }}
									<span class="badge {isAdd ? 'badge-group' : 'badge-locked'}">
										{isAdd ? '➕ Join' : '➖ Leave'}: {group}
								</span>
							{/each}
							</div>
						</div>
					{/if}
					
					<div class="flex flex-wrap gap-3 mt-4">
						<button class="btn-secondary" type="button" on:click={handleApproveUpdate} disabled={saving}><Check size={18} />Approve</button>
						<button class="btn-danger" type="button" on:click={handleRejectUpdate} disabled={saving}><X size={18} />Reject</button>
					</div>
				</div>
			{/if}

			<div class="card-muted space-y-4 mt-6">
				<h2 class="section-title">Edit User</h2>
				<form class="space-y-4" on:submit|preventDefault={handleUpdate}>
					<label class="flex flex-col gap-2 text-sm text-muted">
						Status
						<select class="input" bind:value={status}>
							<option value="ok">OK</option>
							<option value="locked by admin">Locked by Admin</option>
							<option value="pending admin approval">Pending Approval</option>
						</select>
					</label>
					<label class="flex flex-row items-center gap-2 text-sm text-muted">
						<input class="h-4 w-4 rounded border-borderc bg-input" type="checkbox" bind:checked={mfaEnforced} />
						Enforce MFA
					</label>

					{#if availablePermissions.length > 0}
						<div class="edit-section">
							<h3>Permissions</h3>
							<div class="mb-3">
								<input 
									type="text" 
									class="input" 
									placeholder="Search permissions..." 
									bind:value={permissionSearch}
								/>
							</div>
							<div class="chip-selection">
								{#each availablePermissions.filter(p => 
									!permissionSearch || 
									p.name.toLowerCase().includes(permissionSearch.toLowerCase()) ||
									p.key.toLowerCase().includes(permissionSearch.toLowerCase()) ||
									(p.description && p.description.toLowerCase().includes(permissionSearch.toLowerCase()))
								) as perm}
									<button
										type="button"
										class="chip-selectable {editPermissions[perm.key] ? 'chip-selected chip-permission' : 'chip-unselected'}"
										on:click={() => editPermissions[perm.key] = !editPermissions[perm.key]}
										title={perm.description}
									>
										{#if editPermissions[perm.key]}
											<span class="chip-check">✓</span>
										{/if}
										{perm.name}
									</button>
								{/each}
							</div>
						</div>
					{/if}

					{#if availableGroups.length > 0}
						<div class="edit-section">
							<h3>Groups</h3>
							<div class="mb-3">
								<input 
									type="text" 
									class="input" 
									placeholder="Search groups..." 
									bind:value={groupSearch}
								/>
							</div>
							<div class="chip-selection">
								{#each availableGroups.filter(g => 
									!groupSearch || 
									g.name.toLowerCase().includes(groupSearch.toLowerCase()) ||
									g.key.toLowerCase().includes(groupSearch.toLowerCase()) ||
									(g.description && g.description.toLowerCase().includes(groupSearch.toLowerCase()))
								) as group}
									<button
										type="button"
										class="chip-selectable {editGroups[group.key] ? 'chip-selected chip-group' : 'chip-unselected'}"
										on:click={() => editGroups[group.key] = !editGroups[group.key]}
										title={group.description}
									>
										{#if editGroups[group.key]}
											<span class="chip-check">✓</span>
										{/if}
										{group.name}
									</button>
								{/each}
							</div>
						</div>
					{/if}

					<button class="btn-secondary min-w-[9rem]" type="submit" disabled={saving}>
						<Save size={18} />
						{saving ? 'Saving...' : 'Save Changes'}
					</button>
				</form>
			</div>

			<div class="card-muted space-y-4 mt-6">
				<h2 class="section-title">Security Actions</h2>
				<div class="flex flex-wrap items-center gap-3">
					{#if $currentUser?.mfa_enabled}
						<label class="flex flex-col gap-2 text-sm text-muted w-full sm:w-auto">
							<span>Your MFA Code (for security actions)</span>
							<input class="input" type="text" bind:value={mfaCode} placeholder="6-digit code" />
						</label>
					{/if}
				</div>
				<div class="flex flex-wrap gap-3">
					<button class="btn-danger bg-red-600 border-red-500 hover:-translate-y-[1px]" type="button" on:click={handleRevokeSessions} disabled={saving}>
						<LogOut size={18} />
						Revoke All Sessions
					</button>
					<button class="btn-danger bg-red-700 border-red-600 hover:-translate-y-[1px]" type="button" on:click={requestDeleteConfirmation} disabled={saving}>
						<Trash2 size={18} />
						Delete User
					</button>
				</div>
			</div>
		{/if}
	</div>
</div>

{#if showToast}
	<div class="toast toast-{toastType}">
		{toastMessage}
	</div>
{/if}

<ConfirmModal 
	bind:open={showDeleteConfirm}
	title="Delete User"
	message="Are you sure you want to delete this user? This action cannot be undone. All user data, sessions, and security records will be permanently removed."
	confirmText="Delete User"
	confirmClass="btn-danger"
	on:confirm={handleDelete}
/>

<style>
	.edit-section {
		margin: 1.5rem 0;
		padding: 1rem;
		background: var(--bg-input);
		border-radius: var(--radius);
	}

	.edit-section h3 {
		margin: 0 0 1rem 0;
		color: var(--text-muted);
		font-size: 0.9rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.checkbox-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
		gap: 0.75rem;
	}

	.checkbox-label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		padding: 0.5rem;
		border-radius: 4px;
		transition: background 0.2s;
	}

	.checkbox-label:hover {
		background: var(--bg);
	}

	.checkbox-label input[type="checkbox"] {
		width: 18px;
		height: 18px;
		cursor: pointer;
	}

	.checkbox-label span {
		color: var(--text);
		font-size: 0.9rem;
	}
</style>

{#if showToast}
	<div class="toast" class:toast-success={toastType === 'success'} class:toast-error={toastType === 'error'}>
		{toastMessage}
	</div>
{/if}

<ConfirmModal 
	bind:open={showDeleteConfirm}
	title="Delete User"
	message="Are you sure you want to delete this user? This action cannot be undone. All user data, sessions, and security records will be permanently removed."
	confirmText="Delete User"
	confirmClass="btn-danger"
	on:confirm={handleDelete}
/>

