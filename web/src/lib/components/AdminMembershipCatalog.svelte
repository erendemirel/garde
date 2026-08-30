<script>
	import { onMount } from 'svelte';
	import { listPermissions, listGroups, listUsers, updateUser } from '$lib/api';
	import { user } from '$lib/stores';
	import { Users, Save, X } from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';

	/** @type {'permissions' | 'groups'} */
	export let mode = 'permissions';

	let loading = true;
	let error = '';
	/** @type {{ key: string, name: string, description?: string }[]} */
	let catalog = [];
	/** @type {{ id: string, email: string, status?: string, permissions?: Record<string, boolean>, groups?: Record<string, boolean> }[]} */
	let manageableUsers = [];
	let search = '';

	let showToast = false;
	let toastMessage = '';
	let toastType = 'success';

	let showManageUsersModal = false;
	let showMembershipSaveConfirm = false;
	let membershipSaving = false;
	/** @type {{ type: 'permission' | 'group', name: string } | null} */
	let managingMembership = null;
	/** @type {Set<string>} */
	let selectedMembers = new Set();
	/** @type {Set<string>} */
	let initialMembers = new Set();

	$: adminGroupKeys = new Set(
		Object.entries($user?.groups || {})
			.filter(([, enabled]) => enabled)
			.map(([name]) => name)
	);

	$: title = mode === 'permissions' ? 'Permissions' : 'Groups';
	$: subtitle =
		mode === 'permissions'
			? 'Assign permissions you can see to users you manage.'
			: 'Assign your groups to users you manage.';

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

	$: userOptions = manageableUsers.map((u) => ({
		key: u.id,
		name: u.email,
		description: u.status || undefined
	}));

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
		void reload();
	});

	let lastMode = mode;
	$: if (mode !== lastMode) {
		lastMode = mode;
		search = '';
		void reload();
	}

	async function reload() {
		loading = true;
		error = '';
		try {
			const [catalogRes, usersRes] = await Promise.all([
				mode === 'permissions' ? listPermissions() : listGroups(),
				listUsers()
			]);
			const items = catalogRes || [];
			if (mode === 'groups') {
				catalog = items.filter(
					(g) => adminGroupKeys.has(g.name) || adminGroupKeys.has(g.key)
				);
			} else {
				catalog = items;
			}
			manageableUsers = usersRes.users || [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load data';
			catalog = [];
			manageableUsers = [];
		}
		loading = false;
	}

	function enabledKeys(/** @type {Record<string, boolean> | undefined} */ map) {
		return Object.fromEntries(Object.entries(map || {}).filter(([, enabled]) => enabled));
	}

	function userEmail(/** @type {string} */ id) {
		return manageableUsers.find((u) => u.id === id)?.email || id;
	}

	function showToastMessage(message, type = 'success') {
		toastMessage = message;
		toastType = type;
		showToast = true;
		setTimeout(() => {
			showToast = false;
		}, 5000);
	}

	function openManageUsers(item) {
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
			showToastMessage('No changes to save', 'error');
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
				showToastMessage(
					`Updated with ${failed} failure(s)${lastError ? `: ${lastError}` : ''}`,
					'error'
				);
				await reload();
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
				showToastMessage(
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

<div class="space-y-4">
	<div>
		<h2 class="section-title">{title}</h2>
		<p class="text-sm text-muted mt-1">{subtitle}</p>
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
							{#if mode === 'groups'}
								You are not in any groups yet. A superuser must assign groups before you can manage
								membership.
							{:else}
								No permissions visible to your groups.
							{/if}
						</td>
					</tr>
				{:else if filteredCatalog.length === 0}
					<tr>
						<td colspan="4" class="text-center text-muted py-4">No matches for your search.</td>
					</tr>
				{:else}
					{#each filteredCatalog as item}
						<tr>
							<td class="font-medium whitespace-nowrap">{item.name}</td>
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
	{/if}
</div>

<Modal
	bind:open={showManageUsersModal}
	title={manageUsersTitle}
	labelledBy="admin-manage-users-title"
	wide
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
			<p class="text-xs text-muted -mt-2">
				Only users you already manage appear here. Search to add them; remove with ×. Newly added chips
				are yellow with +; removed ones stay yellow with − until you restore them or save.
			</p>
			{#if userOptions.length === 0}
				<p class="text-sm text-muted">No manageable users available.</p>
			{:else}
				<MultiSelectChips
					options={userOptions}
					bind:selected={selectedMembers}
					initial={initialMembers}
					variant={managingMembership.type === 'permission' ? 'permission' : 'group'}
					placeholder="Search users to add…"
					label="Users"
				/>
			{/if}
			<ChangeSummary
				title="Pending save"
				items={memberChangeItems}
				emptyText="No unsaved membership changes."
				on:revert={revertMemberChange}
			/>
			<div class="form-actions">
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
					<Save size={18} class="-ml-0.5" />
					{membershipSaving ? 'Saving...' : membershipDirty ? 'Save Changes' : 'No changes'}
				</button>
			</div>
		</div>
	{/if}
</Modal>

<ConfirmModal
	bind:open={showMembershipSaveConfirm}
	title="Confirm membership changes"
	message={membershipSaveMessage}
	confirmText="Save Changes"
	confirmClass="btn-primary"
	on:confirm={saveMembership}
/>

{#if showToast}
	<div class="toast" class:toast-success={toastType === 'success'} class:toast-error={toastType === 'error'}>
		{toastMessage}
	</div>
{/if}
