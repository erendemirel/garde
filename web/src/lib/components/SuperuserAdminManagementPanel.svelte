<script>
	import { onMount } from 'svelte';
	import { listGroups, updateUser, getAdminUserManagement } from '$lib/api';
	import { showToast } from '$lib/toast';
	import { loadUsersAllPages } from '$lib/usersLoad';
	import { Eye, UserPen, X } from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';
	import TablePagination from '$lib/components/TablePagination.svelte';

	let loading = true;
	let error = '';
	/** @type {Record<string, string[]>} */
	let adminUserManagement = {};
	/** @type {{ id: string, email: string, status?: string, is_admin?: boolean, groups?: Record<string, boolean> }[]} */
	let usersCache = [];
	let usersLoadPromise = /** @type {Promise<void> | null} */ (null);
	/** @type {{ key: string, name: string, description?: string }[]} */
	let groups = [];

	let adminManagementSearch = '';
	let adminManagementPage = 1;
	let adminManagementPageSize = 30;

	let showManageableUsersModal = false;
	/** @type {{ adminEmail: string, userEmails: string[] } | null} */
	let viewingManageableUsers = null;
	let manageableUsersSearch = '';

	let showManageUsersModal = false;
	let showMembershipSaveConfirm = false;
	let membershipSaving = false;
	/** @type {{ type: 'admin-groups', name: string, userId: string } | null} */
	let managingMembership = null;
	/** @type {Set<string>} */
	let selectedMembers = new Set();
	/** @type {Set<string>} */
	let initialMembers = new Set();

	$: groupNameOptions = groups.map((g) => ({
		key: g.name,
		name: g.name,
		description: g.description || undefined
	}));

	$: adminManagementRows = (() => {
		/** @type {Map<string, string[]>} */
		const byEmail = new Map();
		for (const [adminEmail, userEmails] of Object.entries(adminUserManagement)) {
			byEmail.set(adminEmail, Array.isArray(userEmails) ? userEmails : []);
		}
		for (const user of usersCache) {
			if (!user.is_admin) continue;
			if (!byEmail.has(user.email)) byEmail.set(user.email, []);
		}
		return [...byEmail.entries()]
			.map(([adminEmail, userEmails]) => ({ adminEmail, userEmails }))
			.sort((a, b) => a.adminEmail.localeCompare(b.adminEmail));
	})();

	$: filteredAdminManagementRows = (() => {
		const q = adminManagementSearch.trim().toLowerCase();
		if (!q) return adminManagementRows;
		return adminManagementRows.filter(
			(row) =>
				row.adminEmail.toLowerCase().includes(q) ||
				row.userEmails.some((email) => String(email).toLowerCase().includes(q))
		);
	})();

	$: {
		void adminManagementSearch;
		adminManagementPage = 1;
	}

	$: pagedAdminManagementRows = (() => {
		const size = Number(adminManagementPageSize) || 30;
		const start = (adminManagementPage - 1) * size;
		return filteredAdminManagementRows.slice(start, start + size);
	})();

	$: filteredManageableUserEmails = (() => {
		if (!viewingManageableUsers) return [];
		const q = manageableUsersSearch.trim().toLowerCase();
		const emails = viewingManageableUsers.userEmails;
		if (!q) return emails;
		return emails.filter((email) => String(email).toLowerCase().includes(q));
	})();

	$: memberAdds = [...selectedMembers].filter((id) => !initialMembers.has(id));
	$: memberRemoves = [...initialMembers].filter((id) => !selectedMembers.has(id));
	$: memberChangeItems = [
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
	];
	$: membershipDirty = memberChangeItems.length > 0;
	$: membershipSaveMessage = managingMembership
		? `Save changes for groups of admin "${managingMembership.name}"?\n\n${memberChangeItems
				.map((i) => `• ${i.kind === 'add' ? 'Add' : 'Remove'}: ${i.label}`)
				.join('\n')}`
		: '';
	$: manageUsersTitle = managingMembership
		? `Manage groups for admin: ${managingMembership.name}`
		: 'Manage groups';

	onMount(() => {
		void loadAdminData();
	});

	async function loadAdminData() {
		loading = true;
		error = '';
		try {
			const [mgmt, grps] = await Promise.all([
				getAdminUserManagement().catch(() => ({})),
				listGroups().catch(() => [])
			]);
			adminUserManagement = mgmt || {};
			groups = grps || [];
			// Admins with no manageable users only appear once usersCache is populated.
			await ensureUsersLoaded();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load data';
			adminUserManagement = {};
			groups = [];
		}
		loading = false;
	}

	function ensureUsersLoaded() {
		if (usersLoadPromise) return usersLoadPromise;
		usersLoadPromise = (async () => {
			try {
				usersCache = await loadUsersAllPages();
			} catch {
				usersCache = [];
			}
		})();
		return usersLoadPromise;
	}

	async function refreshUsersCache() {
		usersLoadPromise = null;
		await ensureUsersLoaded();
	}

	async function loadAdminUserManagement() {
		try {
			adminUserManagement = await getAdminUserManagement();
		} catch {
			adminUserManagement = {};
		}
	}

	function enabledKeys(/** @type {Record<string, boolean> | undefined} */ map) {
		return Object.fromEntries(Object.entries(map || {}).filter(([, enabled]) => enabled));
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

	async function openManageAdminGroups(adminEmail) {
		await ensureUsersLoaded();
		const admin = usersCache.find((u) => u.email === adminEmail);
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

	function revertMemberChange(event) {
		const item = event.detail;
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

	async function saveAdminGroupsAssignment(userId, adds, removes) {
		const user = usersCache.find((u) => u.id === userId);
		if (!user) return { failed: 1, lastError: 'Admin user not found' };
		const groupsMap = { ...enabledKeys(user.groups) };
		for (const groupName of adds) groupsMap[groupName] = true;
		for (const groupName of removes) delete groupsMap[groupName];
		try {
			await updateUser(userId, { groups: groupsMap });
			user.groups = groupsMap;
			usersCache = [...usersCache];
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
				const admin = usersCache.find((u) => u.id === managingMembership?.userId);
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

<div class="space-y-4" data-testid="superuser-admin-management-panel">
	<div>
		<h2 class="section-title">Admin-User Management</h2>
		<p class="text-sm text-muted mt-1">
			Derived from shared groups: each admin can manage users who share at least one group with them.
			Editing an admin’s groups changes that scope.
		</p>
	</div>

	{#if loading}
		<p class="text-muted" data-testid="admin-mgmt-loading">Loading...</p>
	{:else if error}
		<p class="error" data-testid="admin-mgmt-error">{error}</p>
	{:else}
		<label class="form-label max-w-md">
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
											on:click={() => openManageableUsersModal(row)}
										>
											<Eye size={20} />
										</button>
										<button
											class="btn-icon"
											type="button"
											title="Manage groups of the admin"
											aria-label="Manage groups of the admin {row.adminEmail}"
											data-testid="admin-mgmt-edit-groups"
											on:click={() => openManageAdminGroups(row.adminEmail)}
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
	{/if}
</div>

<Modal
	bind:open={showManageableUsersModal}
	title={viewingManageableUsers
		? `Manageable users for admin: ${viewingManageableUsers.adminEmail}`
		: 'Manageable users'}
	labelledBy="manageable-users-title"
	wide
	on:close={closeManageableUsersModal}
>
	<button
		slot="header-end"
		type="button"
		class="text-muted hover:text-accent"
		on:click={closeManageableUsersModal}
		aria-label="Close"
	>
		<X size={20} />
	</button>
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
					on:click={closeManageableUsersModal}>Close</button
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
	on:close={closeManageUsersModal}
>
	<button
		slot="header-end"
		type="button"
		class="text-muted hover:text-accent"
		on:click={closeManageUsersModal}
		aria-label="Close"
	>
		<X size={20} />
	</button>
	{#if managingMembership}
		<div class="space-y-4" data-testid="admin-mgmt-groups-modal">
			<p class="text-xs text-muted">
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
				on:revert={revertMemberChange}
			/>
		</div>
	{/if}
	<div slot="footer" class="contents">
		{#if managingMembership}
			<button
				type="button"
				class="btn-secondary"
				data-testid="admin-mgmt-groups-cancel"
				on:click={closeManageUsersModal}
				disabled={membershipSaving}>Cancel</button
			>
			<button
				type="button"
				class="btn-primary"
				data-testid="admin-mgmt-groups-save"
				on:click={requestMembershipSave}
				disabled={membershipSaving || !membershipDirty}
			>
				{membershipSaving ? 'Saving...' : membershipDirty ? 'Save Changes' : 'No changes'}
			</button>
		{/if}
	</div>
</Modal>

<ConfirmModal
	bind:open={showMembershipSaveConfirm}
	title="Confirm changes"
	message={membershipSaveMessage}
	confirmText="Save Changes"
	confirmClass="btn-primary"
	on:confirm={saveMembership}
/>
