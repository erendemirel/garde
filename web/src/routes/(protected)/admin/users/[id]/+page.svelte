<script>
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { beforeNavigate, goto } from '$app/navigation';
	import { getUser, updateUser, revokeSessions, deleteUser, listPermissions, listGroups } from '$lib/api';
	import { isForbidden } from '$lib/apiError';
	import { showToast } from '$lib/toast';
	import { user as currentUser, isSuperuser } from '$lib/stores';
	import { ArrowLeft, Check, X, LogOut, Trash2, Lock, LockOpen } from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';
	import ShieldLock from '$lib/components/ShieldLock.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import MfaLabel from '$lib/components/MfaLabel.svelte';

	const STATUS_OK = 'ok';
	const STATUS_PENDING = 'pending admin approval';
	const STATUS_REJECTED = 'admin approval rejected';
	const STATUS_LOCKED_ADMIN = 'locked by admin';
	const STATUS_LOCKED_SECURITY = 'locked by security';

	$: usersListHref = $isSuperuser ? '/superuser?tab=users' : '/admin';

	let userData = null;
	let error = '';
	let loading = true;
	let saving = false;
	let accessDenied = false;
	let showDeleteConfirm = false;
	let showSaveConfirm = false;
	let showMfaEnforceConfirm = false;
	let showLockConfirm = false;
	let showApproveConfirm = false;
	let showRejectAccountConfirm = false;
	let showLeaveConfirm = false;
	let showRevokeConfirm = false;
	let showApproveUpdateConfirm = false;
	let showRejectUpdateConfirm = false;
	let pendingMfaEnforced = false;
	/** true = lock account, false = unlock */
	let pendingLock = false;
	let pendingLeaveHref = '';
	let allowNextNavigation = false;
	let dirty = false;

	let mfaCode = '';

	let availablePermissions = [];
	let availableGroups = [];

	/** @type {Set<string>} */
	let selectedPermissions = new Set();
	/** @type {Set<string>} */
	let initialPermissions = new Set();
	/** @type {Set<string>} */
	let selectedGroups = new Set();
	/** @type {Set<string>} */
	let initialGroups = new Set();

	$: userId = $page.params.id;
	$: accountStatus = (userData?.status || '').toLowerCase();
	$: isLockedByAdmin = accountStatus === STATUS_LOCKED_ADMIN;
	$: isLockedBySecurity = accountStatus === STATUS_LOCKED_SECURITY;
	$: isAccountLocked = isLockedByAdmin || isLockedBySecurity;
	$: isPendingApproval = accountStatus === STATUS_PENDING;
	$: isApprovalRejected = accountStatus === STATUS_REJECTED;
	$: needsAccountApproval = isPendingApproval || isApprovalRejected;
	$: canAdminLock = accountStatus === STATUS_OK;

	$: permissionsAdd = [...selectedPermissions].filter((p) => !initialPermissions.has(p));
	$: permissionsRemove = [...initialPermissions].filter((p) => !selectedPermissions.has(p));
	$: groupsAdd = [...selectedGroups].filter((g) => !initialGroups.has(g));
	$: groupsRemove = [...initialGroups].filter((g) => !selectedGroups.has(g));
	$: accessChanged =
		permissionsAdd.length > 0 ||
		permissionsRemove.length > 0 ||
		groupsAdd.length > 0 ||
		groupsRemove.length > 0;
	$: changeItems = [
		...permissionsAdd.map((p) => ({
			label: permissionLabel(p),
			kind: 'add',
			target: 'permission',
			key: p
		})),
		...permissionsRemove.map((p) => ({
			label: permissionLabel(p),
			kind: 'remove',
			target: 'permission',
			key: p
		})),
		...groupsAdd.map((g) => ({
			label: groupLabel(g),
			kind: 'add',
			target: 'group',
			key: g
		})),
		...groupsRemove.map((g) => ({
			label: groupLabel(g),
			kind: 'remove',
			target: 'group',
			key: g
		}))
	];
	$: hasChanges = changeItems.length > 0;
	$: dirty = hasChanges;
	$: saveConfirmMessage = accessChanged
		? `Save these access changes for ${userData?.email || 'this user'}?\n\n${changeItems.map((i) => `• ${i.label}`).join('\n')}`
		: '';
	$: mfaEnforceConfirmMessage = pendingMfaEnforced
		? 'Require MFA for this user? They must set up MFA before using other features if it is not already enabled.'
		: 'Stop requiring MFA for this user? They can disable MFA themselves afterward if it is enabled.';
	$: mfaEnforceConfirmTitle = pendingMfaEnforced ? 'Enforce MFA' : 'Remove MFA enforcement';
	$: mfaEnforceConfirmText = pendingMfaEnforced ? 'Enforce MFA' : 'Remove enforcement';
	$: lockConfirmTitle = pendingLock
		? 'Lock account'
		: isLockedByAdmin
			? 'Unlock account anyway'
			: 'Unlock account';
	$: lockConfirmMessage = pendingLock
		? 'Lock this user as an admin? They will not be able to sign in until unlocked.'
		: isLockedBySecurity
			? 'Unlock this security-locked account? Status will be set to OK and they can sign in again.'
			: 'Unlock this admin-locked account anyway? Status will be set to OK and they can sign in again.';
	$: lockConfirmText = pendingLock
		? 'Lock account'
		: isLockedByAdmin
			? 'Unlock account anyway'
			: 'Unlock account';

	beforeNavigate(({ to, cancel }) => {
		if (allowNextNavigation) {
			allowNextNavigation = false;
			return;
		}
		if (!dirty) return;
		cancel();
		pendingLeaveHref = to ? `${to.url.pathname}${to.url.search}` : usersListHref;
		showLeaveConfirm = true;
	});

	function permissionLabel(key) {
		return availablePermissions.find((p) => p.key === key)?.name || key;
	}

	function groupLabel(key) {
		return availableGroups.find((g) => g.key === key)?.name || key;
	}

	function enabledKeys(map) {
		return new Set(
			Object.entries(map || {})
				.filter(([, enabled]) => enabled)
				.map(([key]) => key)
		);
	}

	function confirmLeave() {
		showLeaveConfirm = false;
		allowNextNavigation = true;
		const href = pendingLeaveHref || usersListHref;
		pendingLeaveHref = usersListHref;
		goto(href);
	}

	function cancelLeave() {
		showLeaveConfirm = false;
		pendingLeaveHref = usersListHref;
	}

	function snapshotBaseline(user) {
		initialPermissions = enabledKeys(user.permissions);
		selectedPermissions = new Set(initialPermissions);
		initialGroups = enabledKeys(user.groups);
		selectedGroups = new Set(initialGroups);
	}

	function applyUser(user) {
		userData = user;
		snapshotBaseline(user);
	}

	function togglePermission(key) {
		if (selectedPermissions.has(key)) {
			selectedPermissions.delete(key);
		} else {
			selectedPermissions.add(key);
		}
		selectedPermissions = new Set(selectedPermissions);
	}

	function toggleGroup(key) {
		if (selectedGroups.has(key)) {
			selectedGroups.delete(key);
		} else {
			selectedGroups.add(key);
		}
		selectedGroups = new Set(selectedGroups);
	}

	function revertChange(event) {
		const item = event.detail;
		if (!item?.key || !item?.target) return;
		if (item.target === 'permission') {
			togglePermission(item.key);
		} else if (item.target === 'group') {
			toggleGroup(item.key);
		}
	}

	function buildAccessMaps() {
		// PUT replaces the whole maps — send only enabled keys.
		// Including every catalog key as false races with parallel catalog deletes
		// ("invalid permission/group requested" for a name that disappeared mid-edit).
		/** @type {Record<string, boolean>} */
		const permissions = {};
		for (const key of selectedPermissions) {
			permissions[key] = true;
		}
		/** @type {Record<string, boolean>} */
		const groups = {};
		for (const key of selectedGroups) {
			groups[key] = true;
		}
		return { permissions, groups };
	}

	onMount(async () => {
		const onBeforeUnload = (e) => {
			if (!dirty) return;
			e.preventDefault();
			e.returnValue = '';
		};
		window.addEventListener('beforeunload', onBeforeUnload);

		try {
			const [perms, grps, user] = await Promise.all([
				listPermissions().catch(() => []),
				listGroups().catch(() => []),
				getUser(userId)
			]);

			availablePermissions = perms || [];
			availableGroups = grps || [];
			applyUser(user);
		} catch (e) {
			if (isForbidden(e)) {
				accessDenied = true;
			} else {
				error = e instanceof Error ? e.message : 'Failed to load user';
			}
		}
		loading = false;

		return () => {
			window.removeEventListener('beforeunload', onBeforeUnload);
		};
	});

	function requestSave() {
		if (!hasChanges) {
			showToast('No changes to save', 'error');
			return;
		}
		if (accessChanged) {
			showSaveConfirm = true;
			return;
		}
		handleUpdate();
	}

	async function handleUpdate() {
		saving = true;
		showSaveConfirm = false;
		const summary = changeItems.map((i) => i.label).join('; ');
		try {
			const { permissions, groups } = buildAccessMaps();
			const updatedUser = await updateUser(userId, { permissions, groups });
			showToast(summary ? `Updated: ${summary}` : 'User updated!', 'success');
			if (updatedUser) {
				applyUser(updatedUser);
			} else {
				const fresh = await getUser(userId);
				if (fresh) applyUser(fresh);
			}
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Update failed', 'error');
		}
		saving = false;
	}

	function requestApproveUpdate() {
		showApproveUpdateConfirm = true;
	}

	function requestRejectUpdate() {
		showRejectUpdateConfirm = true;
	}

	async function handleApproveUpdate() {
		saving = true;
		showApproveUpdateConfirm = false;
		try {
			const updatedUser = await updateUser(userId, { approve_update: true });
			showToast('Update approved!', 'success');
			if (updatedUser) {
				applyUser(updatedUser);
			} else {
				const fresh = await getUser(userId);
				if (fresh) applyUser(fresh);
			}
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Approval failed', 'error');
		}
		saving = false;
	}

	async function handleRejectUpdate() {
		saving = true;
		showRejectUpdateConfirm = false;
		try {
			const updatedUser = await updateUser(userId, { reject_update: true });
			showToast('Update rejected!', 'success');
			if (updatedUser) {
				applyUser(updatedUser);
			} else {
				const fresh = await getUser(userId);
				if (fresh) applyUser(fresh);
			}
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Rejection failed', 'error');
		}
		saving = false;
	}

	function requestRevokeSessions() {
		if ($currentUser?.mfa_enabled && !mfaCode.trim()) {
			showToast('Enter your MFA code to revoke sessions', 'error');
			return;
		}
		showRevokeConfirm = true;
	}

	async function handleRevokeSessions() {
		saving = true;
		showRevokeConfirm = false;
		try {
			await revokeSessions(userId, $currentUser?.mfa_enabled ? mfaCode : undefined);
			showToast('Sessions revoked!', 'success');
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to revoke sessions', 'error');
		}
		saving = false;
	}

	function requestMfaEnforceToggle() {
		pendingMfaEnforced = !userData?.mfa_enforced;
		showMfaEnforceConfirm = true;
	}

	function requestLockToggle() {
		if (isAccountLocked) {
			pendingLock = false;
			showLockConfirm = true;
			return;
		}
		if (!canAdminLock) return;
		pendingLock = true;
		showLockConfirm = true;
	}

	function requestApproveAccount() {
		showApproveConfirm = true;
	}

	function requestRejectAccount() {
		showRejectAccountConfirm = true;
	}

	async function handleApproveAccount() {
		saving = true;
		showApproveConfirm = false;
		try {
			const updatedUser = await updateUser(userId, { status: STATUS_OK });
			showToast('Account approved', 'success');
			if (updatedUser) {
				applyUser(updatedUser);
			} else {
				const fresh = await getUser(userId);
				if (fresh) applyUser(fresh);
			}
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to approve account', 'error');
		}
		saving = false;
	}

	async function handleRejectAccount() {
		saving = true;
		showRejectAccountConfirm = false;
		try {
			const updatedUser = await updateUser(userId, { status: STATUS_REJECTED });
			showToast('Account approval rejected', 'success');
			if (updatedUser) {
				applyUser(updatedUser);
			} else {
				const fresh = await getUser(userId);
				if (fresh) applyUser(fresh);
			}
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to reject account', 'error');
		}
		saving = false;
	}

	async function handleLockConfirm() {
		saving = true;
		showLockConfirm = false;
		try {
			const updatedUser = await updateUser(userId, {
				status: pendingLock ? STATUS_LOCKED_ADMIN : STATUS_OK
			});
			showToast(pendingLock ? 'Account locked by admin' : 'Account unlocked', 'success');
			if (updatedUser) {
				applyUser(updatedUser);
			} else {
				const fresh = await getUser(userId);
				if (fresh) applyUser(fresh);
			}
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to update lock status', 'error');
		}
		saving = false;
	}

	async function handleMfaEnforceConfirm() {
		saving = true;
		showMfaEnforceConfirm = false;
		try {
			const updatedUser = await updateUser(userId, { mfa_enforced: pendingMfaEnforced });
			showToast(
				pendingMfaEnforced ? 'MFA enforcement enabled' : 'MFA enforcement removed',
				'success'
			);
			if (updatedUser) {
				userData = updatedUser;
			} else {
				const fresh = await getUser(userId);
				if (fresh) userData = fresh;
			}
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to update MFA enforcement', 'error');
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
			showToast('User deleted successfully!', 'success');
			allowNextNavigation = true;
			setTimeout(() => {
				goto(usersListHref);
			}, 1500);
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Failed to delete user', 'error');
			saving = false;
		}
	}
</script>

<svelte:head>
	<title>User Details | garde</title>
</svelte:head>

<div class="container-medium space-y-4" data-testid="user-detail-page">
	<div class="card space-y-4">
		{#if loading}
			<p class="text-muted" data-testid="user-detail-loading">Loading...</p>
		{:else if accessDenied}
			<h1 class="page-title text-error" data-testid="user-detail-access-denied">Access Denied</h1>
			<p class="text-muted mb-4">
				You don't have permission to view this user. Admin privileges are required.
			</p>
			<a href="/dashboard" class="btn-secondary" data-testid="user-detail-back-dashboard"
				><ArrowLeft size={18} />Back to Dashboard</a
			>
		{:else if error && !userData}
			<p class="error" data-testid="user-detail-error">{error}</p>
			<div class="links">
				<a href={usersListHref} data-testid="user-detail-back">Back to users</a>
			</div>
		{:else if userData}
			<div class="flex items-start justify-between gap-3">
				<div>
					<h1 class="page-title">User Details</h1>
					<p class="section-subtitle">Review and edit user access</p>
				</div>
				<a
					href={usersListHref}
					class="btn-secondary w-full sm:w-auto sm:ml-auto"
					data-testid="user-detail-back"
					><ArrowLeft size={18} />Back to users</a
				>
			</div>

			<div class="info-grid">
				<div class="info-card">
					<p class="info-label">ID</p>
					<p class="info-value font-mono text-[13px]" data-testid="user-detail-id">{userData.id}</p>
				</div>
				<div class="info-card">
					<p class="info-label">Email</p>
					<p class="info-value" data-testid="user-detail-email">{userData.email}</p>
				</div>
				<div class="info-card">
					<p class="info-label">Status</p>
					<p class="info-value" data-testid="user-detail-status">
						<StatusBadge status={userData.status} />
					</p>
				</div>
				<div class="info-card">
					<p class="info-label">MFA</p>
					<p class="info-value" data-testid="user-detail-mfa">
						<MfaLabel enabled={userData.mfa_enabled} enforced={userData.mfa_enforced} />
					</p>
				</div>
				<div class="info-card">
					<p class="info-label">Created</p>
					<p class="info-value">{new Date(userData.created_at).toLocaleString()}</p>
				</div>
				<div class="info-card">
					<p class="info-label">Last Login</p>
					<p class="info-value"
						>{userData.last_login ? new Date(userData.last_login).toLocaleString() : 'Never'}</p
					>
				</div>
			</div>

			{#if needsAccountApproval}
				<div
					class="card-muted space-y-3 my-6 border {isApprovalRejected
						? 'border-red-200/80 bg-red-50/40'
						: 'border-orange-200/80 bg-orange-50/50'}"
					data-testid="user-detail-account-approval"
					data-approval-state={isApprovalRejected ? 'rejected' : 'pending'}
				>
					<div class="flex flex-col sm:flex-row sm:items-center gap-3">
						<div class="flex-1 min-w-0">
							<p class="text-sm font-semibold text-text">
								{isApprovalRejected
									? 'Approval rejected by an admin'
									: 'Pending approval by an admin'}
							</p>
							<p class="text-xs text-muted mt-0.5">
								{#if isApprovalRejected}
									This account was rejected and cannot sign in. Approve anyway to activate, or delete
									the account under Security Actions.
								{:else}
									New accounts start pending and cannot sign in until approved. Approve to activate,
									or reject to leave them blocked.
								{/if}
							</p>
						</div>
						<div class="flex flex-wrap gap-2">
							<button
								class="btn-secondary min-w-[11.5rem] justify-center"
								type="button"
								data-testid="user-detail-approve-account"
								on:click={requestApproveAccount}
								disabled={saving}
							>
								<Check size={16} />
								{isApprovalRejected ? 'Approve account anyway' : 'Approve account'}
							</button>
							{#if isPendingApproval}
								<button
									class="btn-danger min-w-[11.5rem] justify-center"
									type="button"
									data-testid="user-detail-reject-account"
									on:click={requestRejectAccount}
									disabled={saving}
								>
									<X size={16} />
									Reject account
								</button>
							{/if}
						</div>
					</div>
				</div>
			{/if}

			{#if userData.pending_updates}
				{@const fields = userData.pending_updates.fields || {}}

				{@const permissionChanges = (() => {
					const changes = [];
					if (fields.permissions_add) {
						fields.permissions_add.forEach((perm) => changes.push({ perm, isAdd: true }));
					}
					if (fields.permissions_remove) {
						fields.permissions_remove.forEach((perm) => changes.push({ perm, isAdd: false }));
					}
					return changes;
				})()}

				{@const groupChanges = (() => {
					const changes = [];
					if (fields.groups_add) {
						fields.groups_add.forEach((group) => changes.push({ group, isAdd: true }));
					}
					if (fields.groups_remove) {
						fields.groups_remove.forEach((group) => changes.push({ group, isAdd: false }));
					}
					return changes;
				})()}

				<div class="card-muted space-y-4 my-6" data-testid="user-detail-pending-update">
					<h2 class="section-title text-warning">Pending Update Request</h2>
					<p class="text-xs text-muted">
						Requested: {new Date(userData.pending_updates.requested_at).toLocaleString()}
					</p>

					{#if permissionChanges.length > 0}
						<div class="space-y-3" data-testid="user-detail-pending-permissions">
							<p class="text-sm font-semibold text-text">Permissions:</p>
							<div class="flex flex-wrap gap-2">
								{#each permissionChanges as { perm, isAdd }}
									<span
										class="badge {isAdd ? 'badge-permission' : 'badge-locked'}"
										data-testid="user-detail-pending-perm"
										data-key={perm}
										data-kind={isAdd ? 'add' : 'remove'}
									>
										{isAdd ? 'Add' : 'Remove'}: {perm}
									</span>
								{/each}
							</div>
						</div>
					{/if}

					{#if groupChanges.length > 0}
						<div class="space-y-3" data-testid="user-detail-pending-groups">
							<p class="text-sm font-semibold text-text">Groups:</p>
							<div class="flex flex-wrap gap-2">
								{#each groupChanges as { group, isAdd }}
									<span
										class="badge {isAdd ? 'badge-group' : 'badge-locked'}"
										data-testid="user-detail-pending-group"
										data-key={group}
										data-kind={isAdd ? 'add' : 'remove'}
									>
										{isAdd ? 'Join' : 'Leave'}: {group}
									</span>
								{/each}
							</div>
						</div>
					{/if}

					<div class="flex flex-wrap gap-3 mt-4">
						<button
							class="btn-secondary"
							type="button"
							data-testid="user-detail-approve-update"
							on:click={requestApproveUpdate}
							disabled={saving}
							><Check size={18} />Approve</button
						>
						<button
							class="btn-danger"
							type="button"
							data-testid="user-detail-reject-update"
							on:click={requestRejectUpdate}
							disabled={saving}
							><X size={18} />Reject</button
						>
					</div>
				</div>
			{/if}

			<div class="card-muted space-y-4 mt-6">
				<h2 class="section-title">Edit User</h2>
				<p class="text-xs text-muted">
					Permissions control what this user can do. Groups control which admins can manage them and which
					permissions are visible. As an admin you can only grant permissions visible to your groups, and
					only add groups you belong to.
				</p>
				<form
					class="space-y-4"
					data-testid="user-detail-access-form"
					method="post"
					action="#"
					onsubmit="return false;"
					on:submit|preventDefault={requestSave}
				>
					{#if availablePermissions.length > 0}
						<div class="edit-section" data-testid="user-detail-permissions">
							<h3>Permissions</h3>
							<MultiSelectChips
								options={availablePermissions}
								bind:selected={selectedPermissions}
								initial={initialPermissions}
								variant="permission"
								placeholder="Search permissions to add…"
								label="Permissions"
							/>
						</div>
					{/if}

					{#if availableGroups.length > 0}
						<div class="edit-section" data-testid="user-detail-groups">
							<h3>Groups</h3>
							<MultiSelectChips
								options={availableGroups}
								bind:selected={selectedGroups}
								initial={initialGroups}
								variant="group"
								placeholder="Search groups to add…"
								label="Groups"
							/>
						</div>
					{/if}

					<ChangeSummary
						title="Pending save"
						items={changeItems}
						emptyText="No unsaved changes."
						on:revert={revertChange}
					/>

					<button
						class="btn-secondary min-w-[9rem]"
						type="submit"
						data-testid="user-detail-save"
						disabled={saving || !hasChanges}
					>
						{saving ? 'Saving...' : hasChanges ? 'Save Changes' : 'No changes'}
					</button>
				</form>
			</div>
		{/if}
	</div>

	{#if userData && !loading && !accessDenied}
		<div class="card space-y-4" data-testid="user-detail-security">
			<div>
				<h1 class="page-title">Security Actions</h1>
				<p class="section-subtitle">Manage lock state, MFA policy, sessions, and account removal of this user.</p>
			</div>

			{#if $currentUser?.mfa_enabled}
				<label class="flex flex-col gap-1.5 text-sm text-muted max-w-xs">
					<span>Your MFA code</span>
					<input
						class="input"
						type="text"
						data-testid="user-detail-mfa-code"
						bind:value={mfaCode}
						placeholder="Required for revoke"
					/>
				</label>
			{/if}

			<div class="rounded-lg border border-borderc divide-y divide-borderc overflow-hidden bg-input/40">
				<div
					class="flex flex-col sm:flex-row sm:items-center gap-3 p-4"
					data-testid="user-detail-lock-row"
					data-lock-state={isLockedBySecurity
						? 'locked-security'
						: isLockedByAdmin
							? 'locked-admin'
							: 'unlocked'}
				>
					<div class="flex-1 min-w-0">
						<p class="text-sm font-semibold text-text">
							Account lock
							{#if isLockedBySecurity}
								<span class="ml-2 text-xs font-medium text-muted" data-testid="user-detail-lock-status"
									>Current status: <span class="text-red-600">locked by security</span></span
								>
							{:else if isLockedByAdmin}
								<span class="ml-2 text-xs font-medium text-muted" data-testid="user-detail-lock-status"
									>Current status: <span class="text-red-600">locked by an admin</span></span
								>
							{:else}
								<span class="ml-2 text-xs font-medium text-muted" data-testid="user-detail-lock-status"
									>Current status: <span class="text-green-700">not locked</span></span
								>
							{/if}
						</p>
						<p class="text-xs text-muted mt-0.5">
							{#if isLockedBySecurity}
								Locked after failed logins or reset abuse. Unlock sets status to OK so they can sign in
								again.
							{:else if isLockedByAdmin}
								Admin lock is active. Unlock sets status to OK so they can sign in again.
							{:else if needsAccountApproval}
								Approve the account first. Admin lock is available once the account is active (OK).
							{:else}
								Prevent this user from signing in (admin lock). Takes effect immediately.
							{/if}
						</p>
					</div>
					{#if isAccountLocked}
						<button
							class="security-action-btn inline-flex items-center justify-center gap-1.5 rounded-md border border-accent/50 bg-transparent px-3.5 py-2.5 text-sm font-semibold text-accent shadow-none w-[14rem] min-w-[14rem] transition-all duration-150 ease-out hover:bg-accent/5 hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed"
							type="button"
							data-testid="user-detail-lock-btn"
							data-action="unlock"
							on:click={requestLockToggle}
							disabled={saving}
						>
							<LockOpen size={16} />
							{isLockedByAdmin ? 'Unlock account anyway' : 'Unlock account'}
						</button>
					{:else if canAdminLock}
						<button
							class="security-action-btn inline-flex items-center justify-center gap-1.5 rounded-md border border-accent/50 bg-transparent px-3.5 py-2.5 text-sm font-semibold text-accent shadow-none w-[14rem] min-w-[14rem] transition-all duration-150 ease-out hover:bg-accent/5 hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed"
							type="button"
							data-testid="user-detail-lock-btn"
							data-action="lock"
							on:click={requestLockToggle}
							disabled={saving}
						>
							<Lock size={16} />
							Lock account
						</button>
					{/if}
				</div>
				<div
					class="flex flex-col sm:flex-row sm:items-center gap-3 p-4"
					data-testid="user-detail-mfa-enforce-row"
					data-enforced={userData.mfa_enforced ? 'true' : 'false'}
				>
					<div class="flex-1 min-w-0">
						<p class="text-sm font-semibold text-text">
							Enforce MFA
							{#if userData.mfa_enforced}
								<span
									class="ml-2 text-xs font-medium text-muted"
									data-testid="user-detail-mfa-enforce-status"
									>Current status: <span class="text-green-700">enforced</span></span
								>
							{:else}
								<span
									class="ml-2 text-xs font-medium text-muted"
									data-testid="user-detail-mfa-enforce-status"
									>Current status: <span class="text-orange-500">not enforced</span></span
								>
							{/if}
						</p>
						<p class="text-xs text-muted mt-0.5">
							{#if userData.mfa_enforced}
								This user must keep MFA enabled. Turn off enforcement to make MFA optional again.
							{:else}
								Require this user to set up and use MFA. Takes effect immediately.
							{/if}
						</p>
					</div>
					<button
						class="security-action-btn inline-flex items-center justify-center gap-1.5 rounded-md border border-accent/50 bg-transparent px-3.5 py-2.5 text-sm font-semibold text-accent shadow-none w-[14rem] min-w-[14rem] transition-all duration-150 ease-out hover:bg-accent/5 hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed"
						type="button"
						data-testid="user-detail-mfa-enforce-btn"
						data-action={userData.mfa_enforced ? 'stop' : 'enforce'}
						on:click={requestMfaEnforceToggle}
						disabled={saving}
					>
						<ShieldLock size={16} />
						{userData.mfa_enforced ? 'Stop enforcing' : 'Enforce MFA'}
					</button>
				</div>
			</div>

			<div class="rounded-lg border border-red-200/80 divide-y divide-red-100 overflow-hidden bg-red-50/40">
				<div class="flex flex-col sm:flex-row sm:items-center gap-3 p-4" data-testid="user-detail-revoke-row">
					<div class="flex-1 min-w-0">
						<p class="text-sm font-semibold text-text">Revoke all sessions</p>
						<p class="text-xs text-muted mt-0.5">
							Signs this user out everywhere. They can sign in again with their credentials.
						</p>
					</div>
					<button
						class="security-action-btn inline-flex items-center justify-center gap-1.5 rounded-md border border-red-700 bg-transparent px-3.5 py-2.5 text-sm font-semibold text-red-700 shadow-none w-[14rem] min-w-[14rem] transition-all duration-150 ease-out hover:bg-red-50 hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed"
						type="button"
						data-testid="user-detail-revoke-btn"
						on:click={requestRevokeSessions}
						disabled={saving}
					>
						<LogOut size={16} />
						Revoke All Sessions
					</button>
				</div>
				<div class="flex flex-col sm:flex-row sm:items-center gap-3 p-4" data-testid="user-detail-delete-row">
					<div class="flex-1 min-w-0">
						<p class="text-sm font-semibold text-text">Delete user</p>
						<p class="text-xs text-muted mt-0.5">
							Permanently removes the account, sessions, and security records. Cannot be undone.
						</p>
					</div>
					<button
						class="security-action-btn inline-flex items-center justify-center gap-1.5 rounded-md border border-red-700 bg-red-700 px-3.5 py-2.5 text-sm font-semibold text-white shadow-none w-[14rem] min-w-[14rem] transition-all duration-150 ease-out hover:bg-red-800 hover:border-red-800 hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed"
						type="button"
						data-testid="user-detail-delete-btn"
						on:click={requestDeleteConfirmation}
						disabled={saving}
					>
						<Trash2 size={16} />
						Delete User
					</button>
				</div>
			</div>
		</div>
	{/if}
</div>

<ConfirmModal
	bind:open={showSaveConfirm}
	title="Confirm access changes"
	message={saveConfirmMessage}
	confirmText="Save Changes"
	on:confirm={handleUpdate}
/>

<ConfirmModal
	bind:open={showMfaEnforceConfirm}
	title={mfaEnforceConfirmTitle}
	message={mfaEnforceConfirmMessage}
	confirmText={mfaEnforceConfirmText}
	on:confirm={handleMfaEnforceConfirm}
/>

<ConfirmModal
	bind:open={showLockConfirm}
	title={lockConfirmTitle}
	message={lockConfirmMessage}
	confirmText={lockConfirmText}
	confirmClass="btn-primary"
	on:confirm={handleLockConfirm}
/>

<ConfirmModal
	bind:open={showApproveConfirm}
	title={isApprovalRejected ? 'Approve account anyway' : 'Approve account'}
	message={isApprovalRejected
		? 'Approve this rejected account anyway? Status will be set to OK and the user can sign in.'
		: 'Approve this account? Status will be set to OK and the user can sign in.'}
	confirmText={isApprovalRejected ? 'Approve account anyway' : 'Approve account'}
	confirmClass="btn-primary"
	on:confirm={handleApproveAccount}
/>

<ConfirmModal
	bind:open={showRejectAccountConfirm}
	title="Reject account"
	message="Reject this account? Status will be set to Approval rejected by an admin and they will not be able to sign in until approved later."
	confirmText="Reject account"
	confirmClass="btn-danger"
	on:confirm={handleRejectAccount}
/>

<ConfirmModal
	bind:open={showLeaveConfirm}
	title="Unsaved changes"
	message="You have unsaved edits on this user. Leave without saving?"
	confirmText="Leave without saving"
	cancelText="Stay"
	confirmClass="btn-primary"
	on:confirm={confirmLeave}
	on:cancel={cancelLeave}
/>

<ConfirmModal
	bind:open={showApproveUpdateConfirm}
	title="Approve update request"
	message="Approve this user's pending permission and group changes? The request will be applied immediately."
	confirmText="Approve request"
	confirmClass="btn-primary"
	on:confirm={handleApproveUpdate}
/>

<ConfirmModal
	bind:open={showRejectUpdateConfirm}
	title="Reject update request"
	message="Reject this user's pending permission and group changes? They will need to submit a new request."
	confirmText="Reject request"
	confirmClass="btn-danger"
	on:confirm={handleRejectUpdate}
/>

<ConfirmModal
	bind:open={showRevokeConfirm}
	title="Revoke all sessions"
	message="Sign this user out everywhere? They can sign in again with their credentials."
	confirmText="Revoke sessions"
	confirmClass="btn-danger"
	on:confirm={handleRevokeSessions}
/>

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
</style>
