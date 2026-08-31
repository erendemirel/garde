<script>
	import { onMount } from 'svelte';
	import { listPermissions, listGroups, updateUser } from '$lib/api';
	import { showToast } from '$lib/toast';
	import { loadUsersAllPages, searchUsers } from '$lib/usersLoad';
	import { user } from '$lib/stores';
	import { Users, X } from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';
	import TablePagination from '$lib/components/TablePagination.svelte';

	/** @type {'permissions' | 'groups'} */
	export let mode = 'permissions';

	let loading = true;
	let error = '';
	/** @type {{ key: string, name: string, description?: string }[]} */
	let catalog = [];
	/** @type {{ id: string, email: string, status?: string, permissions?: Record<string, boolean>, groups?: Record<string, boolean> }[]} */
	let manageableUsers = [];
	let usersLoadPromise = /** @type {Promise<void> | null} */ (null);
	let search = '';
	let catalogPage = 1;
	let catalogPageSize = 30;

	let showManageUsersModal = false;
	let showMembershipSaveConfirm = false;
	let membershipSaving = false;
	/** @type {{ type: 'permission' | 'group', name: string } | null} */
	let managingMembership = null;
	/** @type {Set<string>} */
	let selectedMembers = new Set();
	/** @type {Set<string>} */
	let initialMembers = new Set();
	/** @type {{ key: string, name: string, description?: string }[]} */
	let searchHitOptions = [];

	$: adminGroupKeys = new Set(
		Object.entries($user?.groups || {})
			.filter(([, enabled]) => enabled)
			.map(([name]) => name)
	);

	$: title = mode === 'permissions' ? 'Permissions' : 'Groups';
	$: subtitle =
		mode === 'permissions'
			? 'Permissions visible to your groups. You can grant them only to users you already manage (shared group).'
			: 'Groups you belong to. You can add manageable users to these groups, or remove group membership within your scope.';

	$: filteredCatalog = (() => {
		const q = search.trim().toLowerCase();
		const rows = catalog;
		if (!q) return rows;
		return rows.filter(
			(item) =>
				(item.name || '').toLowerCase().includes(q) ||
				(item.description || '').toLowerCase().includes(q)
		);
	})();

	$: {
		void search;
		catalogPage = 1;
	}

	$: pagedCatalog = (() => {
		const size = Number(catalogPageSize) || 30;
		const start = (catalogPage - 1) * size;
		return filteredCatalog.slice(start, start + size);
	})();

	$: userCounts = (() => {
		/** @type {Record<string, number>} */
		const counts = {};
		for (const u of manageableUsers) {
			const map = mode === 'permissions' ? u.permissions : u.groups;
			for (const [key, enabled] of Object.entries(map || {})) {
				if (!enabled) continue;
				counts[key] = (counts[key] || 0) + 1;
			}
		}
		return counts;
	})();

	$: pickerOptions = (() => {
		/** @type {Map<string, { key: string, name: string, description?: string }>} */
		const byId = new Map();
		for (const u of manageableUsers) {
			if (selectedMembers.has(u.id) || initialMembers.has(u.id)) {
				byId.set(u.id, {
					key: u.id,
					name: u.email,
					description: u.status || undefined
				});
			}
		}
		for (const opt of searchHitOptions) {
			byId.set(opt.key, opt);
		}
		return [...byId.values()];
	})();

	$: memberAdds = [...selectedMembers].filter((id) => !initialMembers.has(id));
	$: memberRemoves = [...initialMembers].filter((id) => !selectedMembers.has(id));
	$: memberChangeItems = [
		...memberAdds.map((id) => ({
			label: userEmail(id),
			kind: 'add',
			target: 'user',
			key: id
		})),
		...memberRemoves.map((id) => ({
			label: userEmail(id),
			kind: 'remove',
			target: 'user',
			key: id
		}))
	];
	$: membershipDirty = memberChangeItems.length > 0;
	$: membershipSaveMessage = managingMembership
		? `Save membership changes for ${managingMembership.type} "${managingMembership.name}"?\n\n${memberChangeItems
				.map((i) => `• ${i.kind === 'add' ? 'Add' : 'Remove'}: ${i.label}`)
				.join('\n')}`
		: '';
	$: manageUsersTitle = managingMembership
		? managingMembership.type === 'permission'
			? `Manage users for permission: ${managingMembership.name}`
			: `Manage users for group: ${managingMembership.name}`
		: 'Manage users';

	onMount(() => {
		void (async () => {
			await reloadCatalog();
			ensureUsersLoaded();
		})();
	});

	let lastMode = mode;
	$: if (mode !== lastMode) {
		lastMode = mode;
		search = '';
		void (async () => {
			await reloadCatalog();
			usersLoadPromise = null;
			ensureUsersLoaded();
		})();
	}

	async function reloadCatalog() {
		loading = true;
		error = '';
		try {
			const items = mode === 'permissions' ? await listPermissions() : await listGroups();
			if (mode === 'groups') {
				catalog = (items || []).filter(
					(g) => adminGroupKeys.has(g.name) || adminGroupKeys.has(g.key)
				);
			} else {
				catalog = items || [];
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load data';
			catalog = [];
		}
		loading = false;
	}

	function ensureUsersLoaded() {
		if (usersLoadPromise) return usersLoadPromise;
		usersLoadPromise = (async () => {
			try {
				manageableUsers = await loadUsersAllPages();
			} catch {
				manageableUsers = [];
			}
		})();
		return usersLoadPromise;
	}

	async function refreshUsersCache() {
		usersLoadPromise = null;
		await ensureUsersLoaded();
	}

	function enabledKeys(/** @type {Record<string, boolean> | undefined} */ map) {
		return Object.fromEntries(Object.entries(map || {}).filter(([, enabled]) => enabled));
	}

	function userEmail(/** @type {string} */ id) {
		const fromCache = manageableUsers.find((u) => u.id === id)?.email;
		if (fromCache) return fromCache;
		return searchHitOptions.find((o) => o.key === id)?.name || id;
	}

	function mergeUsersIntoCache(
		/** @type {{ id: string, email: string, status?: string, permissions?: Record<string, boolean>, groups?: Record<string, boolean> }[]} */ users
	) {
		if (!users.length) return;
		const byId = new Map(manageableUsers.map((u) => [u.id, u]));
		for (const u of users) byId.set(u.id, u);
		manageableUsers = [...byId.values()];
	}

	async function handleUserSearch(event) {
		const q = String(event.detail ?? '');
		if (q.trim().length < 2) {
			searchHitOptions = [];
			return;
		}
		try {
			const hits = await searchUsers(q);
			mergeUsersIntoCache(hits);
			searchHitOptions = hits.map((u) => ({
				key: u.id,
				name: u.email,
				description: u.status || undefined
			}));
		} catch {
			searchHitOptions = [];
		}
	}

	async function openManageUsers(item) {
		await ensureUsersLoaded();
		const type = mode === 'permissions' ? 'permission' : 'group';
		managingMembership = { type, name: item.name };
		const members = new Set(
			manageableUsers
				.filter((u) =>
					type === 'permission' ? u.permissions?.[item.name] : u.groups?.[item.name]
				)
				.map((u) => u.id)
		);
		initialMembers = new Set(members);
		selectedMembers = new Set(members);
		searchHitOptions = [];
		showManageUsersModal = true;
	}

	function closeManageUsersModal() {
		showManageUsersModal = false;
		managingMembership = null;
		selectedMembers = new Set();
		initialMembers = new Set();
		searchHitOptions = [];
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

	async function saveMembership() {
		if (!managingMembership || !membershipDirty) return;
		membershipSaving = true;
		showMembershipSaveConfirm = false;
		const targetName = managingMembership.name;
		const targetType = managingMembership.type;
		const adds = [...memberAdds];
		const removes = [...memberRemoves];
		let failed = 0;
		let lastError = '';

		try {
			for (const id of adds) {
				const u = manageableUsers.find((x) => x.id === id);
				if (!u) continue;
				try {
					if (targetType === 'permission') {
						const permissions = { ...enabledKeys(u.permissions), [targetName]: true };
						await updateUser(id, { permissions });
						u.permissions = permissions;
					} else {
						const groups = { ...enabledKeys(u.groups), [targetName]: true };
						await updateUser(id, { groups });
						u.groups = groups;
					}
				} catch (e) {
					failed += 1;
					lastError = e instanceof Error ? e.message : 'Update failed';
				}
			}
			for (const id of removes) {
				const u = manageableUsers.find((x) => x.id === id);
				if (!u) continue;
				try {
					if (targetType === 'permission') {
						const permissions = { ...enabledKeys(u.permissions) };
						delete permissions[targetName];
						await updateUser(id, { permissions });
						u.permissions = permissions;
					} else {
						const groups = { ...enabledKeys(u.groups) };
						delete groups[targetName];
						await updateUser(id, { groups });
						u.groups = groups;
					}
				} catch (e) {
					failed += 1;
					lastError = e instanceof Error ? e.message : 'Update failed';
				}
			}

			manageableUsers = [...manageableUsers];

			if (failed > 0) {
				showToast(
					`Updated with ${failed} failure(s)${lastError ? `: ${lastError}` : ''}`,
					'error'
				);
				await refreshUsersCache();
				if (managingMembership) {
					const name = managingMembership.name;
					const members = new Set(
						manageableUsers
							.filter((u) =>
								managingMembership.type === 'permission'
									? u.permissions?.[name]
									: u.groups?.[name]
							)
							.map((u) => u.id)
					);
					initialMembers = new Set(members);
					selectedMembers = new Set(members);
				}
			} else {
				const parts = [];
				if (adds.length) parts.push(`+${adds.length}`);
				if (removes.length) parts.push(`−${removes.length}`);
				showToast(
					`Updated ${targetType} "${targetName}" members (${parts.join(', ')})`,
					'success'
				);
				closeManageUsersModal();
			}
		} finally {
			membershipSaving = false;
		}
	}
</script>

<div class="space-y-4" data-testid="admin-catalog" data-mode={mode}>
	<div>
		<h2 class="section-title" data-testid="admin-catalog-title">{title}</h2>
		<p class="text-sm text-muted mt-1">{subtitle}</p>
	</div>

	{#if loading}
		<p class="text-muted" data-testid="admin-catalog-loading">Loading...</p>
	{:else if error}
		<p class="error" data-testid="admin-catalog-error">{error}</p>
	{:else}
		<label class="form-label max-w-md">
			<span>Search</span>
			<input
				class="input"
				type="search"
				data-testid="admin-catalog-search"
				placeholder="Search by name or description..."
				bind:value={search}
			/>
		</label>

		<div class="table-scroll">
			<table class="table-base" data-testid="admin-catalog-table">
				<thead>
					<tr>
						<th>Name</th>
						<th>Description</th>
						<th class="w-24">Users</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody data-testid="admin-catalog-tbody">
					{#if catalog.length === 0}
						<tr data-testid="admin-catalog-empty">
							<td colspan="4" class="text-center text-muted py-4">
								{#if mode === 'groups'}
									You are not in any groups yet. A superuser must assign groups before you can manage
									membership.
								{:else}
									No permissions visible to your groups.
								{/if}
							</td>
						</tr>
					{:else if filteredCatalog.length === 0}
						<tr data-testid="admin-catalog-empty">
							<td colspan="4" class="text-center text-muted py-4">No matches for your search.</td>
						</tr>
					{:else}
						{#each pagedCatalog as item}
							<tr
								data-testid="admin-catalog-row"
								data-item-key={item.key}
								data-item-name={item.name}
							>
								<td class="font-medium whitespace-nowrap" data-testid="admin-catalog-row-name"
									>{item.name}</td
								>
								<td class="text-muted max-w-md truncate" title={item.description || ''}>
									{item.description || '—'}
								</td>
								<td class="tabular-nums">{userCounts[item.name] || 0}</td>
								<td>
									<button
										class="btn-icon"
										type="button"
										title="Manage users"
										aria-label="Manage users for {item.name}"
										data-testid="admin-catalog-manage"
										on:click={() => openManageUsers(item)}
									>
										<Users size={20} />
									</button>
								</td>
							</tr>
						{/each}
					{/if}
				</tbody>
			</table>
		</div>

		<TablePagination
			bind:page={catalogPage}
			bind:pageSize={catalogPageSize}
			total={filteredCatalog.length}
		/>
	{/if}
</div>

<Modal
	bind:open={showManageUsersModal}
	title={manageUsersTitle}
	labelledBy="admin-manage-users-title"
	wide
	preferDialogFocus
	on:close={closeManageUsersModal}
>
	<button
		slot="header-end"
		type="button"
		class="text-muted hover:text-accent"
		data-testid="admin-catalog-modal-close"
		on:click={closeManageUsersModal}
		aria-label="Close"
	>
		<X size={20} />
	</button>
	{#if managingMembership}
		<div class="space-y-4" data-testid="admin-catalog-manage-modal">
			<p class="text-xs text-muted">
				{#if mode === 'permissions'}
					Only users who already share a group with you appear here. Granting a permission applies only if it
					is visible to your groups.
				{:else}
					Only users who already share a group with you appear here. You can add them to groups you belong
					to; removing the last shared group ends your ability to manage that user.
				{/if}
			</p>
			<MultiSelectChips
				options={pickerOptions}
				bind:selected={selectedMembers}
				initial={initialMembers}
				variant={managingMembership.type === 'permission' ? 'permission' : 'group'}
				placeholder="Type email to search users…"
				label="Users"
				remote={true}
				on:search={handleUserSearch}
			/>
			<ChangeSummary
				title="Pending save"
				items={memberChangeItems}
				emptyText="No unsaved membership changes."
				on:revert={revertMemberChange}
			/>
		</div>
	{/if}
	<div slot="footer" class="contents">
		{#if managingMembership}
			<button
				type="button"
				class="btn-secondary"
				data-testid="admin-catalog-manage-cancel"
				on:click={closeManageUsersModal}
				disabled={membershipSaving}>Cancel</button
			>
			<button
				type="button"
				class="btn-primary"
				data-testid="admin-catalog-manage-save"
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
	title="Confirm membership changes"
	message={membershipSaveMessage}
	confirmText="Save Changes"
	confirmClass="btn-primary"
	on:confirm={saveMembership}
/>
