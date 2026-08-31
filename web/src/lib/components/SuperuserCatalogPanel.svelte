<script>
	import { onMount } from 'svelte';
	import {
		listPermissions,
		listGroups,
		createPermission,
		updatePermission,
		deletePermission,
		createGroup,
		updateGroup,
		deleteGroup,
		updateUser
	} from '$lib/api';
	import { showToast } from '$lib/toast';
	import { loadUsersAllPages, searchUsers } from '$lib/usersLoad';
	import { Plus, Edit, Trash2, Users, X } from 'lucide-svelte';
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
	let usersCache = [];
	let usersLoadPromise = /** @type {Promise<void> | null} */ (null);

	let search = '';
	let catalogPage = 1;
	let catalogPageSize = 30;

	let itemName = '';
	let itemDefinition = '';
	let originalItemDefinition = '';
	/** @type {{ key: string, name: string, description?: string } | null} */
	let editingItem = null;
	let showItemModal = false;
	let showDeleteConfirm = false;
	/** @type {{ key: string, name: string, description?: string } | null} */
	let deletingItem = null;

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

	$: title = mode === 'permissions' ? 'Permissions' : 'Groups';
	$: subtitle =
		mode === 'permissions'
			? 'Named application permissions. Assigning a permission to a user grants that capability wherever garde is checked.'
			: 'Groups define admin management scope and permission visibility. Shared group membership is required for an admin to manage a user.';
	$: createLabel = mode === 'permissions' ? 'Create Permission' : 'Create Group';
	$: assignmentHelp =
		mode === 'permissions'
			? 'Users listed here hold this permission. Granting or removing it changes what they can do in applications that check it.'
			: 'Users in this group can be managed by admins who share it, and it affects which permissions are visible to them.';

	$: filteredCatalog = (() => {
		const q = search.trim().toLowerCase();
		if (!q) return catalog;
		return catalog.filter(
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
		for (const u of usersCache) {
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
		for (const u of usersCache) {
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
	$: manageSubjectLabel = managingMembership?.type === 'permission' ? 'permission' : 'group';
	$: membershipSaveMessage = managingMembership
		? `Save changes for ${manageSubjectLabel} "${managingMembership.name}"?\n\n${memberChangeItems
				.map((i) => `• ${i.kind === 'add' ? 'Add' : 'Remove'}: ${i.label}`)
				.join('\n')}`
		: '';
	$: manageUsersTitle = managingMembership
		? managingMembership.type === 'permission'
			? `Manage users for permission: ${managingMembership.name}`
			: `Manage users for group: ${managingMembership.name}`
		: 'Manage users';

	$: itemDirty = editingItem
		? itemDefinition.trim() !== originalItemDefinition.trim()
		: itemName.trim().length > 0 && itemDefinition.trim().length > 0;

	let lastMode = mode;
	$: if (mode !== lastMode) {
		lastMode = mode;
		search = '';
		catalogPage = 1;
		void reloadCatalog();
	}

	onMount(() => {
		void (async () => {
			await reloadCatalog();
			ensureUsersLoaded();
		})();
	});

	async function reloadCatalog() {
		loading = true;
		error = '';
		try {
			const items = mode === 'permissions' ? await listPermissions() : await listGroups();
			catalog = items || [];
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

	function enabledKeys(/** @type {Record<string, boolean> | undefined} */ map) {
		return Object.fromEntries(Object.entries(map || {}).filter(([, enabled]) => enabled));
	}

	function userEmail(/** @type {string} */ id) {
		const fromCache = usersCache.find((u) => u.id === id)?.email;
		if (fromCache) return fromCache;
		return searchHitOptions.find((o) => o.key === id)?.name || id;
	}

	function mergeUsersIntoCache(/** @type {{ id: string, email: string, status?: string, permissions?: Record<string, boolean>, groups?: Record<string, boolean> }[]} */ users) {
		if (!users.length) return;
		const byId = new Map(usersCache.map((u) => [u.id, u]));
		for (const u of users) byId.set(u.id, u);
		usersCache = [...byId.values()];
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
			usersCache
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

	async function saveUserMembership(targetType, targetName, adds, removes) {
		let failed = 0;
		let lastError = '';
		for (const id of adds) {
			const user = usersCache.find((u) => u.id === id);
			if (!user) continue;
			try {
				if (targetType === 'permission') {
					const permissions = { ...enabledKeys(user.permissions), [targetName]: true };
					await updateUser(id, { permissions });
					user.permissions = permissions;
				} else {
					const groups = { ...enabledKeys(user.groups), [targetName]: true };
					await updateUser(id, { groups });
					user.groups = groups;
				}
			} catch (e) {
				failed += 1;
				lastError = e instanceof Error ? e.message : 'Update failed';
			}
		}
		for (const id of removes) {
			const user = usersCache.find((u) => u.id === id);
			if (!user) continue;
			try {
				if (targetType === 'permission') {
					const permissions = { ...enabledKeys(user.permissions) };
					delete permissions[targetName];
					await updateUser(id, { permissions });
					user.permissions = permissions;
				} else {
					const groups = { ...enabledKeys(user.groups) };
					delete groups[targetName];
					await updateUser(id, { groups });
					user.groups = groups;
				}
			} catch (e) {
				failed += 1;
				lastError = e instanceof Error ? e.message : 'Update failed';
			}
		}
		usersCache = [...usersCache];
		return { failed, lastError };
	}

	async function saveMembership() {
		if (!managingMembership || !membershipDirty) return;
		membershipSaving = true;
		showMembershipSaveConfirm = false;
		const targetName = managingMembership.name;
		const targetType = managingMembership.type;
		const adds = [...memberAdds];
		const removes = [...memberRemoves];

		try {
			const { failed, lastError } = await saveUserMembership(
				targetType,
				targetName,
				adds,
				removes
			);

			if (failed > 0) {
				showToast(
					`Updated with ${failed} failure(s)${lastError ? `: ${lastError}` : ''}`,
					'error'
				);
				await refreshUsersCache();
				if (managingMembership) {
					const name = managingMembership.name;
					const members = new Set(
						usersCache
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
					`Updated ${manageSubjectLabel} "${targetName}" members (${parts.join(', ')})`,
					'success'
				);
				closeManageUsersModal();
			}
		} finally {
			membershipSaving = false;
		}
	}

	function openItemModal(item = null) {
		editingItem = item;
		if (item) {
			itemName = item.key;
			itemDefinition = item.description || '';
			originalItemDefinition = item.description || '';
		} else {
			itemName = '';
			itemDefinition = '';
			originalItemDefinition = '';
		}
		showItemModal = true;
	}

	function closeItemModal() {
		showItemModal = false;
		editingItem = null;
		itemName = '';
		itemDefinition = '';
		originalItemDefinition = '';
	}

	async function saveItem() {
		if (!itemName.trim() || !itemDefinition.trim()) {
			showToast('Name and definition are required', 'error');
			return;
		}
		if (editingItem && !itemDirty) {
			showToast('No changes to save', 'error');
			return;
		}
		try {
			if (mode === 'permissions') {
				if (editingItem) {
					await updatePermission(editingItem.key, itemDefinition);
					showToast(`Updated permission "${editingItem.name}"`, 'success');
				} else {
					await createPermission(itemName.trim(), itemDefinition.trim());
					showToast(`Created permission "${itemName.trim()}"`, 'success');
				}
			} else {
				if (editingItem) {
					await updateGroup(editingItem.key, itemDefinition.trim());
					showToast(`Updated group "${editingItem.name}"`, 'success');
				} else {
					await createGroup(itemName.trim(), itemDefinition.trim());
					showToast(`Created group "${itemName.trim()}"`, 'success');
				}
			}
			await reloadCatalog();
			closeItemModal();
		} catch (e) {
			showToast(
				e instanceof Error
					? e.message
					: mode === 'permissions'
						? 'Failed to save permission'
						: 'Failed to save group',
				'error'
			);
		}
	}

	function requestDeleteItem(item) {
		deletingItem = item;
		showDeleteConfirm = true;
	}

	async function handleDeleteItem() {
		if (!deletingItem) return;
		try {
			const name = deletingItem.name;
			if (mode === 'permissions') {
				await deletePermission(deletingItem.key);
				showToast(`Deleted permission "${name}"`, 'success');
			} else {
				await deleteGroup(deletingItem.key);
				showToast(`Deleted group "${name}"`, 'success');
			}
			await reloadCatalog();
			deletingItem = null;
			showDeleteConfirm = false;
		} catch (e) {
			showToast(
				e instanceof Error
					? e.message
					: mode === 'permissions'
						? 'Failed to delete permission'
						: 'Failed to delete group',
				'error'
			);
		}
	}
</script>

<div class="space-y-4">
	<div class="flex justify-between items-center gap-3 flex-wrap">
		<div>
			<h2 class="section-title">{title}</h2>
			<p class="text-sm text-muted mt-1">{subtitle}</p>
		</div>
		<button class="btn-light py-1.5 text-xs" type="button" on:click={() => openItemModal()}>
			<Plus size={16} class="-ml-0.5" />
			{createLabel}
		</button>
	</div>

	{#if loading}
		<p class="text-muted">Loading...</p>
	{:else if error}
		<p class="error">{error}</p>
	{:else}
		<label class="form-label max-w-md">
			<span>Search</span>
			<input
				class="input"
				type="search"
				placeholder="Search by name or description..."
				bind:value={search}
			/>
		</label>

		<div class="table-scroll">
			<table class="table-base">
				<thead>
					<tr>
						<th>Name</th>
						<th>Description</th>
						<th class="w-24">Users</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#if catalog.length === 0}
						<tr>
							<td colspan="4" class="text-center text-muted py-4">
								No {mode} found.
							</td>
						</tr>
					{:else if filteredCatalog.length === 0}
						<tr>
							<td colspan="4" class="text-center text-muted py-4">
								No {mode} match your search.
							</td>
						</tr>
					{:else}
						{#each pagedCatalog as item}
							<tr>
								<td class="font-medium whitespace-nowrap">{item.name}</td>
								<td class="text-muted max-w-md truncate" title={item.description || ''}>
									{item.description || '—'}
								</td>
								<td class="tabular-nums">{userCounts[item.name] || 0}</td>
								<td>
									<div class="flex flex-nowrap gap-0.5">
										<button
											class="btn-icon"
											type="button"
											title="Manage users"
											aria-label="Manage users for {mode === 'permissions'
												? 'permission'
												: 'group'} {item.name}"
											on:click={() => openManageUsers(item)}
										>
											<Users size={20} />
										</button>
										<button
											class="btn-icon"
											type="button"
											title="Edit {mode === 'permissions' ? 'permission' : 'group'}"
											aria-label="Edit {mode === 'permissions'
												? 'permission'
												: 'group'} {item.name}"
											on:click={() => openItemModal(item)}
										>
											<Edit size={20} />
										</button>
										<button
											class="btn-icon-danger"
											type="button"
											title="Delete {mode === 'permissions' ? 'permission' : 'group'}"
											aria-label="Delete {mode === 'permissions'
												? 'permission'
												: 'group'} {item.name}"
											on:click={() => requestDeleteItem(item)}
										>
											<Trash2 size={20} />
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
			bind:page={catalogPage}
			bind:pageSize={catalogPageSize}
			total={filteredCatalog.length}
		/>
	{/if}
</div>

<Modal
	bind:open={showItemModal}
	title={editingItem
		? mode === 'permissions'
			? 'Edit Permission'
			: 'Edit Group'
		: mode === 'permissions'
			? 'Create Permission'
			: 'Create Group'}
	labelledBy="catalog-item-modal-title"
	on:close={closeItemModal}
>
	<button
		slot="header-end"
		type="button"
		class="text-muted hover:text-accent"
		on:click={closeItemModal}
		aria-label="Close"
	>
		<X size={20} />
	</button>
	<div class="space-y-4">
		<label class="form-label">
			<span>Name</span>
			<input
				class="input"
				type="text"
				bind:value={itemName}
				disabled={!!editingItem}
				placeholder={mode === 'permissions' ? 'permission_name' : 'group_name'}
			/>
			{#if editingItem}
				<p class="text-xs text-muted">
					{mode === 'permissions' ? 'Permission' : 'Group'} name cannot be changed
				</p>
			{/if}
		</label>
		<label class="form-label">
			<span>Definition</span>
			<textarea
				class="input"
				bind:value={itemDefinition}
				placeholder="Description of the {mode === 'permissions' ? 'permission' : 'group'}"
				rows="4"
			></textarea>
		</label>
		{#if editingItem && itemDirty}
			<p class="text-sm text-muted">Definition has unsaved changes.</p>
		{/if}
		<div class="form-actions">
			<button type="button" class="btn-secondary" on:click={closeItemModal}>Cancel</button>
			<button type="button" class="btn-primary" on:click={saveItem} disabled={!itemDirty}>
				{editingItem ? (itemDirty ? 'Save Changes' : 'No changes') : 'Create'}
			</button>
		</div>
	</div>
</Modal>

<ConfirmModal
	bind:open={showDeleteConfirm}
	title={mode === 'permissions' ? 'Delete Permission' : 'Delete Group'}
	message={deletingItem
		? `Delete ${mode === 'permissions' ? 'permission' : 'group'} "${deletingItem.name}"? This also removes all visibility mappings for it.`
		: `Delete this ${mode === 'permissions' ? 'permission' : 'group'}?`}
	confirmText="Delete"
	cancelText="Cancel"
	confirmClass="btn-danger"
	on:confirm={handleDeleteItem}
	on:cancel={() => {
		deletingItem = null;
	}}
/>

<Modal
	bind:open={showManageUsersModal}
	title={manageUsersTitle}
	labelledBy="superuser-catalog-manage-users-title"
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
		<div class="space-y-4">
			<p class="text-xs text-muted">{assignmentHelp}</p>
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
				on:click={closeManageUsersModal}
				disabled={membershipSaving}>Cancel</button
			>
			<button
				type="button"
				class="btn-primary"
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
