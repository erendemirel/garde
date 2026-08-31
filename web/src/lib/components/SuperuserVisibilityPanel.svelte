<script>
	import { onMount } from 'svelte';
	import {
		listPermissions,
		listGroups,
		addPermissionVisibility,
		removePermissionVisibility,
		getAllPermissionVisibility
	} from '$lib/api';
	import { showToast } from '$lib/toast';
	import { Edit, Grid3x3, List, Plus, Check, X } from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';
	import TablePagination from '$lib/components/TablePagination.svelte';

	let loading = true;
	let error = '';
	/** @type {{ key: string, name: string, description?: string }[]} */
	let permissions = [];
	/** @type {{ key: string, name: string, description?: string }[]} */
	let groups = [];
	/** @type {Record<string, string[]>} */
	let permissionVisibility = {};

	let visibilityViewMode = 'list';
	let visibilitySearch = '';
	let visibilityPage = 1;
	let visibilityPageSize = 30;

	let showRemoveVisibilityConfirm = false;
	/** @type {{ permissionKey: string, groupKey: string } | null} */
	let pendingVisibilityRemove = null;

	let showManageUsersModal = false;
	let showMembershipSaveConfirm = false;
	let membershipSaving = false;
	/** @type {{ type: 'visibility', name: string, key: string } | null} */
	let managingMembership = null;
	/** @type {Set<string>} */
	let selectedMembers = new Set();
	/** @type {Set<string>} */
	let initialMembers = new Set();

	$: groupOptions = groups.map((g) => ({
		key: g.key,
		name: g.name,
		description: g.description || undefined
	}));

	$: filteredVisibilityPermissions = (() => {
		const q = visibilitySearch.trim().toLowerCase();
		if (!q) return permissions;
		return permissions.filter((p) => {
			if (
				(p.name || '').toLowerCase().includes(q) ||
				(p.description || '').toLowerCase().includes(q)
			) {
				return true;
			}
			const visibleKeys = permissionVisibility[p.key] || [];
			return visibleKeys.some((groupKey) => {
				const group = groups.find((g) => g.key === groupKey);
				return (group?.name || '').toLowerCase().includes(q);
			});
		});
	})();

	$: {
		void visibilitySearch;
		visibilityPage = 1;
	}

	$: pagedVisibilityPermissions = (() => {
		const size = Number(visibilityPageSize) || 30;
		const start = (visibilityPage - 1) * size;
		return filteredVisibilityPermissions.slice(start, start + size);
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
		? `Save changes for visibility of permission "${managingMembership.name}"?\n\n${memberChangeItems
				.map((i) => `• ${i.kind === 'add' ? 'Add' : 'Remove'}: ${i.label}`)
				.join('\n')}`
		: '';
	$: manageUsersTitle = managingMembership
		? `Manage visibility for permission: ${managingMembership.name}`
		: 'Manage visibility';

	$: removeVisibilityMessage = (() => {
		const pending = pendingVisibilityRemove;
		if (!pending) return 'Remove this visibility mapping?';
		const permName =
			permissions.find((p) => p.key === pending.permissionKey)?.name || pending.permissionKey;
		const groupName = groups.find((g) => g.key === pending.groupKey)?.name || pending.groupKey;
		return `Remove visibility of "${permName}" from "${groupName}"?`;
	})();

	onMount(() => {
		void loadData();
	});

	async function loadData() {
		loading = true;
		error = '';
		try {
			const [perms, grps] = await Promise.all([
				listPermissions().catch(() => []),
				listGroups().catch(() => [])
			]);
			permissions = perms || [];
			groups = grps || [];
			await loadVisibilityMappings();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load data';
		}
		loading = false;
	}

	async function loadVisibilityMappings() {
		permissionVisibility = {};
		try {
			const allMappings = await getAllPermissionVisibility();
			const groupNameToKey = new Map(groups.map((g) => [g.name, g.key]));

			permissions.forEach((perm) => {
				const groupNames = allMappings[perm.name] || [];
				permissionVisibility[perm.key] = groupNames
					.map((groupName) => groupNameToKey.get(groupName))
					.filter((key) => key !== undefined);
			});
		} catch {
			permissions.forEach((perm) => {
				permissionVisibility[perm.key] = [];
			});
		}
	}

	function assignmentLabelForKey(/** @type {string} */ key) {
		const fromOpts = groupOptions.find((o) => o.key === key);
		return fromOpts?.name || key;
	}

	function openManageVisibilityGroups(perm) {
		managingMembership = { type: 'visibility', name: perm.name, key: perm.key };
		const members = new Set(permissionVisibility[perm.key] || []);
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

	async function saveVisibilityAssignment(permKey, permName, adds, removes) {
		let failed = 0;
		let lastError = '';
		for (const groupKey of adds) {
			const group = groups.find((g) => g.key === groupKey);
			const groupName = group?.name || groupKey;
			try {
				await addPermissionVisibility(permName, groupName);
				if (!permissionVisibility[permKey]) permissionVisibility[permKey] = [];
				if (!permissionVisibility[permKey].includes(groupKey)) {
					permissionVisibility[permKey] = [...permissionVisibility[permKey], groupKey];
				}
			} catch (e) {
				const msg = e instanceof Error ? e.message : 'Update failed';
				if (msg.includes('already exists') || msg.includes('duplicate')) {
					if (!permissionVisibility[permKey]) permissionVisibility[permKey] = [];
					if (!permissionVisibility[permKey].includes(groupKey)) {
						permissionVisibility[permKey] = [...permissionVisibility[permKey], groupKey];
					}
				} else {
					failed += 1;
					lastError = msg;
				}
			}
		}
		for (const groupKey of removes) {
			const group = groups.find((g) => g.key === groupKey);
			const groupName = group?.name || groupKey;
			try {
				await removePermissionVisibility(permName, groupName);
				permissionVisibility[permKey] = (permissionVisibility[permKey] || []).filter(
					(g) => g !== groupKey
				);
			} catch (e) {
				failed += 1;
				lastError = e instanceof Error ? e.message : 'Update failed';
			}
		}
		permissionVisibility = { ...permissionVisibility };
		return { failed, lastError };
	}

	async function saveMembership() {
		if (!managingMembership || !membershipDirty) return;
		membershipSaving = true;
		showMembershipSaveConfirm = false;
		const targetName = managingMembership.name;
		const adds = [...memberAdds];
		const removes = [...memberRemoves];

		try {
			const permKey = managingMembership.key || targetName;
			const { failed, lastError } = await saveVisibilityAssignment(
				permKey,
				targetName,
				adds,
				removes
			);

			if (failed > 0) {
				showToast(
					`Updated with ${failed} failure(s)${lastError ? `: ${lastError}` : ''}`,
					'error'
				);
				await loadVisibilityMappings();
				if (managingMembership?.key) {
					const members = new Set(permissionVisibility[managingMembership.key] || []);
					initialMembers = new Set(members);
					selectedMembers = new Set(members);
				}
			} else {
				const parts = [];
				if (adds.length) parts.push(`+${adds.length}`);
				if (removes.length) parts.push(`−${removes.length}`);
				showToast(
					`Updated visibility of permission "${targetName}" groups (${parts.join(', ')})`,
					'success'
				);
				closeManageUsersModal();
			}
		} finally {
			membershipSaving = false;
		}
	}

	function requestRemoveVisibility(permissionKey, groupKey) {
		pendingVisibilityRemove = { permissionKey, groupKey };
		showRemoveVisibilityConfirm = true;
	}

	async function handleRemoveVisibilityConfirm() {
		if (!pendingVisibilityRemove) return;
		const { permissionKey, groupKey } = pendingVisibilityRemove;
		pendingVisibilityRemove = null;
		showRemoveVisibilityConfirm = false;
		await removeVisibility(permissionKey, groupKey);
	}

	async function removeVisibility(permissionKey, groupKey) {
		const permName = permissions.find((p) => p.key === permissionKey)?.name || permissionKey;
		const groupNameLabel = groups.find((g) => g.key === groupKey)?.name || groupKey;
		try {
			await removePermissionVisibility(permName, groupNameLabel);
			if (permissionVisibility[permissionKey]) {
				permissionVisibility[permissionKey] = permissionVisibility[permissionKey].filter(
					(g) => g !== groupKey
				);
			}
			showToast(`Visibility: "${permName}" → "${groupNameLabel}" removed`, 'success');
		} catch (e) {
			showToast(
				e instanceof Error ? e.message : 'Failed to remove visibility mapping',
				'error'
			);
		}
	}

	async function toggleVisibility(permissionKey, groupKey) {
		const hasVisibility = permissionVisibility[permissionKey]?.includes(groupKey);
		if (hasVisibility) {
			requestRemoveVisibility(permissionKey, groupKey);
		} else {
			await addVisibilityForGroup(permissionKey, groupKey);
		}
	}

	async function addVisibilityForGroup(permissionKey, groupKey) {
		const permName = permissions.find((p) => p.key === permissionKey)?.name || permissionKey;
		const groupNameLabel = groups.find((g) => g.key === groupKey)?.name || groupKey;
		try {
			await addPermissionVisibility(permName, groupNameLabel);
			if (!permissionVisibility[permissionKey]) {
				permissionVisibility[permissionKey] = [];
			}
			if (!permissionVisibility[permissionKey].includes(groupKey)) {
				permissionVisibility[permissionKey] = [
					...permissionVisibility[permissionKey],
					groupKey
				];
			}
			showToast(`Visibility: "${permName}" → "${groupNameLabel}" added`, 'success');
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'Failed to add visibility mapping';
			if (!msg.includes('already exists') && !msg.includes('duplicate')) {
				showToast(msg, 'error');
			} else {
				if (!permissionVisibility[permissionKey]) {
					permissionVisibility[permissionKey] = [];
				}
				if (!permissionVisibility[permissionKey].includes(groupKey)) {
					permissionVisibility[permissionKey] = [
						...permissionVisibility[permissionKey],
						groupKey
					];
				}
				showToast(`Visibility: "${permName}" → "${groupNameLabel}" added`, 'success');
			}
		}
	}
</script>

<div class="space-y-4">
	<div class="flex justify-between items-center gap-3 flex-wrap">
		<div>
			<h2 class="section-title">Permission Visibility</h2>
			<p class="text-sm text-muted mt-1">
				A permission is usable only by groups linked here. Without a visibility link, regular users
				and admins cannot see or grant that permission.
			</p>
		</div>
		<div class="flex gap-2">
			<button
				class="btn-small {visibilityViewMode === 'list' ? 'bg-accent/20' : ''}"
				type="button"
				on:click={() => (visibilityViewMode = 'list')}
				title="List view"
			>
				<List size={16} />
				List
			</button>
			<button
				class="btn-small {visibilityViewMode === 'matrix' ? 'bg-accent/20' : ''}"
				type="button"
				on:click={() => (visibilityViewMode = 'matrix')}
				title="Matrix view"
			>
				<Grid3x3 size={16} />
				Matrix
			</button>
		</div>
	</div>

	{#if loading}
		<p class="text-muted">Loading...</p>
	{:else if error}
		<p class="error">{error}</p>
	{:else if permissions.length === 0 || groups.length === 0}
		<p class="text-muted">You need at least one permission and one group to manage visibility.</p>
	{:else}
		<label class="form-label max-w-md">
			<span>Search</span>
			<input
				class="input"
				type="search"
				placeholder="Search by permission or group..."
				bind:value={visibilitySearch}
			/>
		</label>

		{#if visibilityViewMode === 'list'}
			<div class="table-scroll">
				<table class="table-base">
					<thead>
						<tr>
							<th>Permission</th>
							<th>Description</th>
							<th>Visible to groups</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
						{#if filteredVisibilityPermissions.length === 0}
							<tr>
								<td colspan="4" class="text-center text-muted py-4">
									No permissions match your search.
								</td>
							</tr>
						{:else}
							{#each pagedVisibilityPermissions as perm}
								{@const visibleGroups = permissionVisibility[perm.key] || []}
								<tr>
									<td class="font-medium whitespace-nowrap">{perm.name}</td>
									<td class="text-muted max-w-md truncate" title={perm.description || ''}>
										{perm.description || '—'}
									</td>
									<td class="tabular-nums">{visibleGroups.length}</td>
									<td>
										<button
											class="btn-icon"
											type="button"
											title="Manage visibility"
											aria-label="Manage visibility for permission {perm.name}"
											on:click={() => openManageVisibilityGroups(perm)}
										>
											<Edit size={20} />
										</button>
									</td>
								</tr>
							{/each}
						{/if}
					</tbody>
				</table>
			</div>
		{:else}
			<div class="table-scroll">
				<table class="table-base">
					<thead>
						<tr>
							<th class="sticky left-0 z-10 bg-input">Permission</th>
							{#each groups as group}
								<th class="!text-center min-w-[100px]">{group.name}</th>
							{/each}
						</tr>
					</thead>
					<tbody>
						{#if filteredVisibilityPermissions.length === 0}
							<tr>
								<td colspan={groups.length + 1} class="text-center text-muted py-4">
									No permissions match your search.
								</td>
							</tr>
						{:else}
							{#each pagedVisibilityPermissions as perm}
								<tr>
									<td class="sticky left-0 z-10 bg-input">
										<div class="font-medium text-gray-600">{perm.name}</div>
										<div class="text-xs text-muted">{perm.description}</div>
									</td>
									{#each groups as group}
										{@const hasVisibility = permissionVisibility[perm.key]?.includes(group.key)}
										<td class="p-2 text-center align-middle">
											<button
												type="button"
												class="mx-auto flex h-6 w-6 items-center justify-center border-0 bg-transparent p-0 transition-transform duration-150 ease-out hover:-translate-y-0.5 motion-reduce:transition-none motion-reduce:hover:translate-y-0 {hasVisibility
													? 'text-accent'
													: 'text-muted opacity-35'}"
												on:click={() => toggleVisibility(perm.key, group.key)}
												title={hasVisibility ? 'Remove visibility' : 'Add visibility'}
												aria-label="{hasVisibility
													? 'Remove'
													: 'Add'} visibility of {perm.name} for {group.name}"
												aria-pressed={hasVisibility}
											>
												{#if hasVisibility}
													<Check size={20} strokeWidth={2.75} />
												{:else}
													<Plus size={18} strokeWidth={2} />
												{/if}
											</button>
										</td>
									{/each}
								</tr>
							{/each}
						{/if}
					</tbody>
				</table>
			</div>
		{/if}

		<TablePagination
			bind:page={visibilityPage}
			bind:pageSize={visibilityPageSize}
			total={filteredVisibilityPermissions.length}
		/>
	{/if}
</div>

<ConfirmModal
	bind:open={showRemoveVisibilityConfirm}
	title="Remove visibility"
	message={removeVisibilityMessage}
	confirmText="Remove"
	confirmClass="btn-danger"
	on:confirm={handleRemoveVisibilityConfirm}
	on:cancel={() => {
		pendingVisibilityRemove = null;
	}}
/>

<Modal
	bind:open={showManageUsersModal}
	title={manageUsersTitle}
	labelledBy="superuser-visibility-manage-title"
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
			<p class="text-xs text-muted">
				Only groups listed here can see this permission and grant it to users. Groups without
				visibility cannot use it.
			</p>
			{#if groupOptions.length === 0}
				<p class="text-sm text-muted">No groups available.</p>
			{:else}
				<MultiSelectChips
					options={groupOptions}
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
