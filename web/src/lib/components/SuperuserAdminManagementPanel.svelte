<script>
	import { onMount } from 'svelte';
	import { listGroups, updateUser, getAdminUserManagement } from '$lib/api';
	import { showToast } from '$lib/toast';
	import { ensureUsersCache, setUsersCache, usersCache, usersCacheError } from '$lib/usersLoad';
	import { enabledKeys } from '$lib/membership';
	import { Eye, UserPen, X } from '@lucide/svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';
	import TablePagination from '$lib/components/TablePagination.svelte';

	let loading = $state(true);
	let error = $state('');
	/** @type {Record<string, string[]>} */
	let adminUserManagement = $state({});
	/** @type {{ key: string, name: string, description?: string }[]} */
	let groups = $state([]);

	let adminManagementSearch = $state('');
	let adminManagementPage = $state(1);
	let adminManagementPageSize = $state(30);

	let showManageableUsersModal = $state(false);
	let viewingManageableUsers = $state(
		/** @type {{ adminEmail: string, userEmails: string[] } | null} */ (null)
	);
	let manageableUsersSearch = $state('');

	let showManageUsersModal = $state(false);
	let showMembershipSaveConfirm = $state(false);
	let membershipSaving = $state(false);
	let managingMembership = $state(
		/** @type {{ type: 'admin-groups', name: string, userId: string } | null} */ (null)
	);
	/** @type {Set<string>} */
	let selectedMembers = $state(new Set());
	/** @type {Set<string>} */
	let initialMembers = $state(new Set());

	let groupNameOptions = $derived(
		groups.map((g) => ({
			key: g.name,
			name: g.name,
			description: g.description || undefined
		}))
	);

	let adminManagementRows = $derived.by(() => {
		/** @type {Map<string, string[]>} */
		const byEmail = new Map();
		for (const [adminEmail, userEmails] of Object.entries(adminUserManagement)) {
			byEmail.set(adminEmail, Array.isArray(userEmails) ? userEmails : []);
		}
		for (const user of $usersCache) {
			if (!user.is_admin) continue;
			if (!byEmail.has(user.email)) byEmail.set(user.email, []);
		}
		return [...byEmail.entries()]
			.map(([adminEmail, userEmails]) => ({ adminEmail, userEmails }))
			.sort((a, b) => a.adminEmail.localeCompare(b.adminEmail));
	});

	let filteredAdminManagementRows = $derived.by(() => {
		const q = adminManagementSearch.trim().toLowerCase();
		if (!q) return adminManagementRows;
		return adminManagementRows.filter(
			(row) =>
				row.adminEmail.toLowerCase().includes(q) ||
				row.userEmails.some((email) => String(email).toLowerCase().includes(q))
		);
	});

	$effect(() => {
		void adminManagementSearch;
		adminManagementPage = 1;
	});

	let pagedAdminManagementRows = $derived.by(() => {
		const size = Number(adminManagementPageSize) || 30;
		const start = (adminManagementPage - 1) * size;
		return filteredAdminManagementRows.slice(start, start + size);
	});

	let filteredManageableUserEmails = $derived.by(() => {
		if (!viewingManageableUsers) return [];
		const q = manageableUsersSearch.trim().toLowerCase();
		const emails = viewingManageableUsers.userEmails;
		if (!q) return emails;
		return emails.filter((email) => String(email).toLowerCase().includes(q));
	});

	let memberAdds = $derived([...selectedMembers].filter((id) => !initialMembers.has(id)));
	let memberRemoves = $derived([...initialMembers].filter((id) => !selectedMembers.has(id)));
	let memberChangeItems = $derived([
		...memberAdds.map((id) => ({
			label: assignmentLabelForKey(id),
			kind: 'add',
			target: 'group',
			key: id
		})),
		...memberRemoves.map((id) => ({
			label: assignmentLabelForKey(id),
			kind: 'remove',
			target: 'group',
			key: id
		}))
	]);
	let membershipDirty = $derived(memberChangeItems.length > 0);
	let membershipSaveMessage = $derived(
		managingMembership
			? `Save changes for groups of admin "${managingMembership.name}"?\n\n${memberChangeItems
					.map((i) => `• ${i.kind === 'add' ? 'Add' : 'Remove'}: ${i.label}`)
					.join('\n')}`
			: ''
	);
	let manageUsersTitle = $derived(
		managingMembership
			? `Manage groups for admin: ${managingMembership.name}`
			: 'Manage groups'
	);

	onMount(() => {
		void loadAdminData();
	});

	async function loadAdminData() {
		loading = true;
		error = '';
		try {
			const [mgmt, grps] = await Promise.all([
				getAdminUserManagement(),
				listGroups()
			]);
			adminUserManagement = mgmt || {};
			groups = grps || [];
			// Admins with no manageable users only appear once usersCache is populated.
			await loadUsers();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load data';
			adminUserManagement = {};
			groups = [];
		}
		loading = false;
	}

	async function loadUsers() {
		try {
			await ensureUsersCache();
		} catch (e) {
			if (!$usersCacheError) {
				showToast(e instanceof Error ? e.message : 'Failed to load users', 'error');
			}
		}
	}

	async function refreshUsersCache() {
		try {
			await ensureUsersCache({ force: true });
		} catch {
			/* usersCacheError store holds the message */
		}
	}

	async function loadAdminUserManagement() {
		try {
			adminUserManagement = await getAdminUserManagement();
		} catch (e) {
			showToast(
				e instanceof Error ? e.message : 'Failed to refresh admin management data',
				'error'
			);
		}
	}

	function assignmentLabelForKey(/** @type {string} */ key) {
		const fromOpts = groupNameOptions.find((o) => o.key === key);
		return fromOpts?.name || key;
	}

	function openManageableUsersModal(/** @type {{ adminEmail: string, userEmails: string[] }} */ row) {
		viewingManageableUsers = row;
		manageableUsersSearch = '';
		showManageableUsersModal = true;
	}

	function closeManageableUsersModal() {
		showManageableUsersModal = false;
		viewingManageableUsers = null;
		manageableUsersSearch = '';
	}

	/** @param {string} adminEmail */
	async function openManageAdminGroups(adminEmail) {
		await loadUsers();
		const admin = $usersCache.find((u) => u.email === adminEmail);
		if (!admin) {
			showToast('Admin user not found in user list', 'error');
			return;
		}
		managingMembership = {
			type: 'admin-groups',
			name: adminEmail,
			userId: admin.id
		};
		const members = new Set(
			Object.entries(admin.groups || {})
				.filter(([, enabled]) => enabled)
				.map(([groupName]) => groupName)
		);
		initialMembers = new Set(members);
		selectedMembers = new Set(members);
		showManageUsersModal = true;
	}

	function closeManageUsersModal() {
		showManageUsersModal = false;
		managingMembership = null;
		selectedMembers = new Set();
		initialMembers = new Set();
		showMembershipSaveConfirm = false;
	}

	function toggleMember(/** @type {string} */ id) {
		if (selectedMembers.has(id)) {
			selectedMembers.delete(id);
		} else {
			selectedMembers.add(id);
		}
		selectedMembers = new Set(selectedMembers);
	}

	/** @param {{ label: string, kind: string, target?: string, key?: string }} item */
	function revertMemberChange(item) {
		if (!item?.key) return;
		toggleMember(item.key);
	}

	function requestMembershipSave() {
		if (!membershipDirty || !managingMembership) {
			showToast('No changes to save', 'error');
			return;
		}
		showMembershipSaveConfirm = true;
	}

	/** @param {string} userId @param {string[]} adds @param {string[]} removes */
	async function saveAdminGroupsAssignment(userId, adds, removes) {
		const user = $usersCache.find((u) => u.id === userId);
		if (!user) return { failed: 1, lastError: 'Admin user not found' };
		const groupsMap = { ...enabledKeys(user.groups) };
		for (const groupName of adds) groupsMap[groupName] = true;
		for (const groupName of removes) delete groupsMap[groupName];
		try {
			await updateUser(userId, { groups: groupsMap });
			user.groups = groupsMap;
			setUsersCache([...$usersCache]);
			await loadAdminUserManagement();
			return { failed: 0, lastError: '' };
		} catch (e) {
			return { failed: 1, lastError: e instanceof Error ? e.message : 'Update failed' };
		}
	}

	async function saveMembership() {
		if (!managingMembership || !membershipDirty) return;
		membershipSaving = true;
		showMembershipSaveConfirm = false;
		const targetName = managingMembership.name;
		const adds = [...memberAdds];
		const removes = [...memberRemoves];

		try {
			const { failed, lastError } = await saveAdminGroupsAssignment(
				managingMembership.userId || '',
				adds,
				removes
			);

			if (failed > 0) {
				showToast(
					`Updated with ${failed} failure(s)${lastError ? `: ${lastError}` : ''}`,
					'error'
				);
				await refreshUsersCache();
				await loadAdminUserManagement();
				const admin = $usersCache.find((u) => u.id === managingMembership?.userId);
				const members = new Set(
					Object.entries(admin?.groups || {})
						.filter(([, enabled]) => enabled)
						.map(([groupName]) => groupName)
				);
				initialMembers = new Set(members);
				selectedMembers = new Set(members);
			} else {
				const parts = [];
				if (adds.length) parts.push(`+${adds.length}`);
				if (removes.length) parts.push(`−${removes.length}`);
				showToast(
					`Updated groups of admin "${targetName}" groups (${parts.join(', ')})`,
					'success'
				);
				closeManageUsersModal();
			}
		} finally {
			membershipSaving = false;
		}
	}
</script>

<div class="list-panel" data-testid="superuser-admin-management-panel">
	<div class="list-panel-header">
		<h2 class="section-title">Admin-User Management</h2>
		<p class="section-subtitle">
			Derived from shared groups: each admin can manage users who share at least one group with them.
			Editing an admin’s groups changes that scope.
		</p>
	</div>

	{#if loading}
		<p class="text-muted" data-testid="admin-mgmt-loading">Loading...</p>
	{:else if error}
		<p class="error" data-testid="admin-mgmt-error">{error}</p>
	{:else if $usersCacheError}
		<p class="error" data-testid="admin-mgmt-users-error">{$usersCacheError}</p>
	{:else}
		<div class="list-panel-body">
		<label class="form-label w-[28rem] max-w-full">
			<span>Search</span>
			<input
				class="input"
				type="search"
				placeholder="Search by admin or user email..."
				data-testid="admin-mgmt-search"
				bind:value={adminManagementSearch}
			/>
		</label>

		<div class="table-scroll" data-testid="admin-mgmt-table">
			<table class="table-base">
				<thead>
					<tr>
						<th>Admin</th>
						<th class="w-36">Manageable users</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#if adminManagementRows.length === 0}
						<tr>
							<td colspan="3" class="text-center text-muted py-4" data-testid="admin-mgmt-empty">
								No admin-user management relationships found.
							</td>
						</tr>
					{:else if filteredAdminManagementRows.length === 0}
						<tr>
							<td
								colspan="3"
								class="text-center text-muted py-4"
								data-testid="admin-mgmt-no-match"
							>
								No admins match your search.
							</td>
						</tr>
					{:else}
						{#each pagedAdminManagementRows as row}
							<tr data-testid="admin-mgmt-row" data-admin-email={row.adminEmail}>
								<td
									class="font-medium whitespace-nowrap"
									data-testid="admin-mgmt-row-email">{row.adminEmail}</td
								>
								<td class="tabular-nums" data-testid="admin-mgmt-row-count"
									>{row.userEmails.length}</td
								>
								<td>
									<div class="flex flex-nowrap gap-0.5">
										<button
											class="btn-icon"
											type="button"
											title="View manageable users"
											aria-label="View manageable users for admin {row.adminEmail}"
											data-testid="admin-mgmt-view-users"
											onclick={() => openManageableUsersModal(row)}
										>
											<Eye size={20} />
										</button>
										<button
											class="btn-icon"
											type="button"
											title="Manage groups of the admin"
											aria-label="Manage groups of the admin {row.adminEmail}"
											data-testid="admin-mgmt-edit-groups"
											onclick={() => openManageAdminGroups(row.adminEmail)}
										>
											<UserPen size={20} />
										</button>
									</div>
								</td>
							</tr>
						{/each}
					{/if}
				</tbody>
			</table>
		</div>

		<TablePagination
			bind:page={adminManagementPage}
			bind:pageSize={adminManagementPageSize}
			total={filteredAdminManagementRows.length}
		/>
		</div>
	{/if}
</div>

<Modal
	bind:open={showManageableUsersModal}
	title={viewingManageableUsers
		? `Manageable users for admin: ${viewingManageableUsers.adminEmail}`
		: 'Manageable users'}
	labelledBy="manageable-users-title"
	wide
	onClose={closeManageableUsersModal}
>
	{#snippet headerEnd()}
		<button
			type="button"
			class="text-muted hover:text-accent"
			onclick={closeManageableUsersModal}
			aria-label="Close"
		>
			<X size={20} />
		</button>
	{/snippet}
	{#if viewingManageableUsers}
		<div class="space-y-4" data-testid="admin-mgmt-users-modal">
			<p class="text-sm text-muted" data-testid="admin-mgmt-users-summary">
				{viewingManageableUsers.userEmails.length} user{viewingManageableUsers.userEmails.length ===
				1
					? ''
					: 's'} share at least one group with this admin, so the admin can manage them.
			</p>
			{#if viewingManageableUsers.userEmails.length > 0}
				<label class="form-label">
					<span>Search</span>
					<input
						class="input"
						type="search"
						placeholder="Filter by email..."
						data-testid="admin-mgmt-users-search"
						bind:value={manageableUsersSearch}
					/>
				</label>
				{#if filteredManageableUserEmails.length === 0}
					<p class="text-sm text-muted" data-testid="admin-mgmt-users-no-match"
						>No users match your search.</p
					>
				{:else}
					<ul
						class="max-h-80 overflow-y-auto divide-y divide-borderc rounded-md border border-borderc"
						data-testid="admin-mgmt-users-list"
					>
						{#each filteredManageableUserEmails as email}
							<li
								class="px-3 py-2 text-sm text-gray-600"
								data-testid="admin-mgmt-users-item"
								data-user-email={email}>{email}</li
							>
						{/each}
					</ul>
				{/if}
			{:else}
				<p class="text-sm text-muted" data-testid="admin-mgmt-users-empty"
					>This admin cannot manage any users yet.</p
				>
			{/if}
			<div class="form-actions">
				<button
					type="button"
					class="btn-secondary"
					data-testid="admin-mgmt-users-close"
					onclick={closeManageableUsersModal}>Close</button
				>
			</div>
		</div>
	{/if}
</Modal>

<Modal
	bind:open={showManageUsersModal}
	title={manageUsersTitle}
	labelledBy="superuser-admin-groups-title"
	wide
	preferDialogFocus
	onClose={closeManageUsersModal}
>
	{#snippet headerEnd()}
		<button
			type="button"
			class="text-muted hover:text-accent"
			onclick={closeManageUsersModal}
			aria-label="Close"
		>
			<X size={20} />
		</button>
	{/snippet}
	{#if managingMembership}
		<div class="space-y-4" data-testid="admin-mgmt-groups-modal">
			<p class="section-subtitle">
				An admin can manage users who share at least one of these groups. Changing membership
				changes that admin’s management scope.
			</p>
			{#if groupNameOptions.length === 0}
				<p class="text-sm text-muted" data-testid="admin-mgmt-groups-empty">No groups available.</p>
			{:else}
				<MultiSelectChips
					options={groupNameOptions}
					bind:selected={selectedMembers}
					initial={initialMembers}
					variant="group"
					placeholder="Search groups to add…"
					label="Groups"
					remote={false}
				/>
			{/if}
			<ChangeSummary
				title="Pending save"
				items={memberChangeItems}
				emptyText="No unsaved changes."
				onRevert={revertMemberChange}
			/>
		</div>
	{/if}
	{#snippet footer()}
		<div class="contents">
			{#if managingMembership}
				<button
					type="button"
					class="btn-secondary"
					data-testid="admin-mgmt-groups-cancel"
					onclick={closeManageUsersModal}
					disabled={membershipSaving}>Cancel</button
				>
				<button
					type="button"
					class="btn-primary"
					data-testid="admin-mgmt-groups-save"
					onclick={requestMembershipSave}
					disabled={membershipSaving || !membershipDirty}
				>
					{membershipSaving ? 'Saving...' : membershipDirty ? 'Save Changes' : 'No changes'}
				</button>
			{/if}
		</div>
	{/snippet}
</Modal>

<ConfirmModal
	bind:open={showMembershipSaveConfirm}
	title="Confirm changes"
	message={membershipSaveMessage}
	confirmText="Save Changes"
	confirmClass="btn-primary"
	onConfirm={saveMembership}
/>
