<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { 
		listPermissions, 
		listGroups, 
		createPermission, 
		updatePermission, 
		deletePermission,
		createGroup,
		updateGroup,
		deleteGroup,
		addPermissionVisibility,
		removePermissionVisibility,
		getAllPermissionVisibility,
		getAllGroupUsers,
		getAdminUserManagement
	} from '$lib/api';
	import { isSuperuser } from '$lib/stores';
	import { 
		Shield, 
		Users, 
		Eye, 
		Plus, 
		Edit, 
		Trash2, 
		X, 
		Check,
		ArrowLeft,
		XCircle,
		Grid3x3,
		List
	} from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';

	let activeTab = 'permissions';
	let loading = true;
	let accessDenied = false;
	let error = '';

	// Permissions
	let permissions = [];
	let permissionName = '';
	let permissionDefinition = '';
	let editingPermission = null;
	let showPermissionModal = false;
	let deletingPermission = null;

	// Groups
	let groups = [];
	let groupName = '';
	let groupDefinition = '';
	let editingGroup = null;
	let showGroupModal = false;
	let deletingGroup = null;

	// Visibility - track which groups each permission is visible to
	let permissionVisibility = {}; // { permission_key: [group_key, ...] }
	let addingVisibilityForPermission = null; // permission key
	let selectedGroupForAdd = '';
	let showAddGroupModal = false;
	let visibilityViewMode = 'list'; // 'list' or 'matrix'

	// Group-User mappings
	let groupUsers = {}; // { group_name: [user_email, ...] }
	
	// Admin-User management mappings
	let adminUserManagement = {}; // { admin_email: [user_email, ...] }

	onMount(async () => {
		try {
			await loadData();
		} catch (e) {
			const msg = e instanceof Error ? e.message : '';
			if (msg.toLowerCase().includes('unauthorized') || 
				msg.toLowerCase().includes('forbidden') ||
				msg.toLowerCase().includes('permission')) {
				accessDenied = true;
				isSuperuser.set(false);
			} else {
				error = msg || 'Failed to load data';
			}
		}
		loading = false;
	});

	async function loadData() {
		const [perms, grps] = await Promise.all([
			listPermissions().catch(() => []),
			listGroups().catch(() => [])
		]);
		permissions = perms || [];
		groups = grps || [];
		await Promise.all([
			loadVisibilityMappings(),
			loadGroupUsers(),
			loadAdminUserManagement()
		]);
	}

	async function loadVisibilityMappings() {
		// Initialize visibility map
		permissionVisibility = {};
		
		// Fetch all visibility mappings in a single request
		try {
			const allMappings = await getAllPermissionVisibility();
			// Convert group names to group keys
			const groupNameToKey = new Map(groups.map(g => [g.name, g.key]));
			
			// Build permissionVisibility map using permission keys and group keys
			permissions.forEach(perm => {
				const groupNames = allMappings[perm.name] || [];
				permissionVisibility[perm.key] = groupNames
					.map(groupName => groupNameToKey.get(groupName))
					.filter(key => key !== undefined);
			});
		} catch (e) {
			// If error, initialize empty arrays for each permission
			permissions.forEach(perm => {
				permissionVisibility[perm.key] = [];
			});
		}
	}

	// Permission functions
	function openPermissionModal(perm = null) {
		editingPermission = perm;
		if (perm) {
			permissionName = perm.key;
			permissionDefinition = perm.description;
		} else {
			permissionName = '';
			permissionDefinition = '';
		}
		showPermissionModal = true;
	}

	function closePermissionModal() {
		showPermissionModal = false;
		editingPermission = null;
		permissionName = '';
		permissionDefinition = '';
	}

	async function savePermission() {
		if (!permissionName.trim() || !permissionDefinition.trim()) {
			error = 'Name and definition are required';
			return;
		}
		try {
			if (editingPermission) {
				await updatePermission(editingPermission.key, permissionDefinition);
			} else {
				await createPermission(permissionName.trim(), permissionDefinition.trim());
			}
			await loadData();
			closePermissionModal();
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save permission';
		}
	}

	async function handleDeletePermission() {
		if (!deletingPermission) return;
		try {
			await deletePermission(deletingPermission.key);
			await loadData();
			deletingPermission = null;
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete permission';
		}
	}

	// Group functions
	function openGroupModal(grp = null) {
		editingGroup = grp;
		if (grp) {
			groupName = grp.key;
			groupDefinition = grp.description;
		} else {
			groupName = '';
			groupDefinition = '';
		}
		showGroupModal = true;
	}

	function closeGroupModal() {
		showGroupModal = false;
		editingGroup = null;
		groupName = '';
		groupDefinition = '';
	}

	async function saveGroup() {
		if (!groupName.trim() || !groupDefinition.trim()) {
			error = 'Name and definition are required';
			return;
		}
		try {
			if (editingGroup) {
				await updateGroup(editingGroup.key, groupDefinition.trim());
			} else {
				await createGroup(groupName.trim(), groupDefinition.trim());
			}
			await loadData();
			closeGroupModal();
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save group';
		}
	}

	async function handleDeleteGroup() {
		if (!deletingGroup) return;
		try {
			await deleteGroup(deletingGroup.key);
			await loadData();
			deletingGroup = null;
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete group';
		}
	}

	// Visibility functions
	function openAddGroupModal(permissionKey) {
		addingVisibilityForPermission = permissionKey;
		selectedGroupForAdd = '';
		showAddGroupModal = true;
	}

	function closeAddGroupModal() {
		showAddGroupModal = false;
		addingVisibilityForPermission = null;
		selectedGroupForAdd = '';
	}

	async function addVisibility() {
		if (!addingVisibilityForPermission || !selectedGroupForAdd) {
			error = 'Please select a group';
			return;
		}
		try {
			await addPermissionVisibility(addingVisibilityForPermission, selectedGroupForAdd);
			// Update local state
			if (!permissionVisibility[addingVisibilityForPermission]) {
				permissionVisibility[addingVisibilityForPermission] = [];
			}
			if (!permissionVisibility[addingVisibilityForPermission].includes(selectedGroupForAdd)) {
				permissionVisibility[addingVisibilityForPermission] = [...permissionVisibility[addingVisibilityForPermission], selectedGroupForAdd];
			}
			closeAddGroupModal();
			error = '';
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'Failed to add visibility mapping';
			// If it's a duplicate, update local state anyway
			if (msg.includes('already exists') || msg.includes('duplicate')) {
				if (!permissionVisibility[addingVisibilityForPermission]) {
					permissionVisibility[addingVisibilityForPermission] = [];
				}
				if (!permissionVisibility[addingVisibilityForPermission].includes(selectedGroupForAdd)) {
					permissionVisibility[addingVisibilityForPermission] = [...permissionVisibility[addingVisibilityForPermission], selectedGroupForAdd];
				}
				closeAddGroupModal();
				error = '';
			} else {
				error = msg;
			}
		}
	}

	async function removeVisibility(permissionKey, groupKey) {
		try {
			await removePermissionVisibility(permissionKey, groupKey);
			// Update local state
			if (permissionVisibility[permissionKey]) {
				permissionVisibility[permissionKey] = permissionVisibility[permissionKey].filter(g => g !== groupKey);
			}
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to remove visibility mapping';
		}
	}

	async function toggleVisibility(permissionKey, groupKey) {
		const hasVisibility = permissionVisibility[permissionKey]?.includes(groupKey);
		if (hasVisibility) {
			await removeVisibility(permissionKey, groupKey);
		} else {
			await addVisibilityForGroup(permissionKey, groupKey);
		}
	}

	async function addVisibilityForGroup(permissionKey, groupKey) {
		try {
			await addPermissionVisibility(permissionKey, groupKey);
			// Update local state
			if (!permissionVisibility[permissionKey]) {
				permissionVisibility[permissionKey] = [];
			}
			if (!permissionVisibility[permissionKey].includes(groupKey)) {
				permissionVisibility[permissionKey] = [...permissionVisibility[permissionKey], groupKey];
			}
			error = '';
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'Failed to add visibility mapping';
			if (!msg.includes('already exists') && !msg.includes('duplicate')) {
				error = msg;
			}
		}
	}

	// Get available groups for a permission (groups not already added)
	$: getAvailableGroupsForPermission = (permissionKey) => {
		const currentGroups = permissionVisibility[permissionKey] || [];
		return groups.filter(g => !currentGroups.includes(g.key));
	};

	async function loadGroupUsers() {
		try {
			groupUsers = await getAllGroupUsers();
		} catch (e) {
			groupUsers = {};
		}
	}

	async function loadAdminUserManagement() {
		try {
			adminUserManagement = await getAdminUserManagement();
		} catch (e) {
			adminUserManagement = {};
		}
	}
</script>

<svelte:head>
	<title>Superuser | garde</title>
</svelte:head>

<div class="container-wide">
	<div class="card space-y-4">
		{#if accessDenied}
			<h1 class="text-xl font-bold text-error">Access Denied</h1>
			<p class="text-muted mb-4">
				You don't have permission to access this page. Superuser privileges are required.
			</p>
			<a href="/dashboard"><button class="btn-secondary">Back to Dashboard</button></a>
		{:else}
			<div class="flex items-start justify-between gap-3">
				<div>
					<h1 class="page-title">Superuser Management</h1>
					<p class="section-subtitle">Manage permissions, groups, and visibility</p>
				</div>
			</div>

			{#if error}
				<div class="error">{error}</div>
			{/if}

			{#if loading}
				<p class="text-muted">Loading...</p>
			{:else}
				<!-- Tabs -->
				<div class="flex gap-2 border-b border-white/10">
					<button
						class="px-4 py-2 font-medium transition-colors {activeTab === 'permissions' ? 'text-accent border-b-2 border-accent' : 'text-muted hover:text-accent'}"
						on:click={() => activeTab = 'permissions'}
					>
						<Shield size={18} class="inline mr-2" />
						Permissions
					</button>
					<button
						class="px-4 py-2 font-medium transition-colors {activeTab === 'groups' ? 'text-accent border-b-2 border-accent' : 'text-muted hover:text-accent'}"
						on:click={() => activeTab = 'groups'}
					>
						<Users size={18} class="inline mr-2" />
						Groups
					</button>
					<button
						class="px-4 py-2 font-medium transition-colors {activeTab === 'visibility' ? 'text-accent border-b-2 border-accent' : 'text-muted hover:text-accent'}"
						on:click={() => activeTab = 'visibility'}
					>
						<Eye size={18} class="inline mr-2" />
						Permission Visibility
					</button>
				</div>

				<!-- Permissions Tab -->
				{#if activeTab === 'permissions'}
					<div class="space-y-4">
						<div class="flex justify-between items-center">
							<h2 class="section-title">Permissions</h2>
							<button class="btn-light px-3 py-1.5 text-xs" on:click={() => openPermissionModal()}>
								<Plus size={16} />
								Create Permission
							</button>
						</div>

						{#if permissions.length === 0}
							<p class="text-muted">No permissions found.</p>
						{:else}
							<div class="space-y-3">
								{#each permissions as perm}
									<div class="flex items-center justify-between p-4 bg-white/5 rounded border border-white/10 transition-colors hover:bg-white/10">
										<div class="flex-1">
											<div class="font-medium text-gray-600">{perm.name}</div>
											<div class="text-sm text-muted">{perm.description}</div>
										</div>
										<div class="flex gap-2">
											<button 
												class="btn-small"
												on:click={() => openPermissionModal(perm)}
											>
												<Edit size={16} />
												Edit
											</button>
											<button 
												class="btn-small text-error"
												on:click={() => deletingPermission = perm}
											>
												<Trash2 size={16} />
												Delete
											</button>
										</div>
									</div>
								{/each}
							</div>
						{/if}
					</div>
				{/if}

				<!-- Groups Tab -->
				{#if activeTab === 'groups'}
					<div class="space-y-4">
						<div class="flex justify-between items-center">
							<div>
								<h2 class="section-title">Groups</h2>
								<p class="text-sm text-muted mt-1">
									Manage groups and see which users belong to each group.
								</p>
							</div>
							<button class="btn-light px-3 py-1.5 text-xs" on:click={() => openGroupModal()}>
								<Plus size={16} />
								Create Group
							</button>
						</div>

						{#if groups.length === 0}
							<p class="text-muted">No groups found.</p>
						{:else}
							<div class="space-y-4">
								{#each groups as grp}
									{@const userEmails = groupUsers[grp.name] || []}
									<div class="p-4 bg-white/5 rounded border border-white/10">
										<div class="flex items-start justify-between mb-3">
											<div class="flex-1">
												<div class="font-medium text-lg text-gray-600">{grp.name}</div>
												<div class="text-sm text-muted mt-1">{grp.description}</div>
											</div>
											<div class="flex gap-2">
												<button 
													class="btn-small"
													on:click={() => openGroupModal(grp)}
												>
													<Edit size={16} />
													Edit
												</button>
												<button 
													class="btn-small text-error"
													on:click={() => deletingGroup = grp}
												>
													<Trash2 size={16} />
													Delete
												</button>
											</div>
										</div>
										<div class="mt-3 pt-3 border-t border-white/10">
											<div class="text-xs text-muted mb-2">Users in this group ({userEmails.length}):</div>
											{#if userEmails.length > 0}
												<div class="flex flex-wrap gap-2">
													{#each userEmails as email}
														<span class="badge badge-group">{email}</span>
													{/each}
												</div>
											{:else}
												<span class="text-xs text-muted italic">No users in this group</span>
											{/if}
										</div>
									</div>
								{/each}
							</div>
						{/if}

						<!-- Admin-User Management Section -->
						<div class="mt-8 pt-6 border-t border-white/10">
							<div class="mb-4">
								<h2 class="section-title">Admin-User Management</h2>
								<p class="text-sm text-muted mt-1">
									See which admins can manage which users (based on shared groups).
								</p>
							</div>

							{#if Object.keys(adminUserManagement).length === 0}
								<p class="text-muted">No admin-user management relationships found.</p>
							{:else}
								<div class="space-y-4">
									{#each Object.entries(adminUserManagement) as [adminEmail, userEmails]}
										<div class="p-4 bg-white/5 rounded border border-white/10">
											<div class="font-medium text-lg mb-3 text-gray-600">{adminEmail}</div>
											<div class="text-xs text-muted mb-2">Can manage ({userEmails.length} users):</div>
											<div class="flex flex-wrap gap-2">
												{#each userEmails as email}
													<span class="badge badge-group">{email}</span>
												{/each}
											</div>
										</div>
									{/each}
								</div>
							{/if}
						</div>
					</div>
				{/if}

				<!-- Visibility Tab -->
				{#if activeTab === 'visibility'}
					<div class="space-y-4">
						<div class="flex justify-between items-center">
							<div>
								<h2 class="section-title">Permission Visibility</h2>
								<p class="text-sm text-muted mt-1">
									Manage which groups can see and manage each permission.
								</p>
							</div>
							<div class="flex gap-2">
								<button
									class="btn-small {visibilityViewMode === 'list' ? 'bg-accent/20' : ''}"
									on:click={() => visibilityViewMode = 'list'}
									title="List view"
								>
									<List size={16} />
									List
								</button>
								<button
									class="btn-small {visibilityViewMode === 'matrix' ? 'bg-accent/20' : ''}"
									on:click={() => visibilityViewMode = 'matrix'}
									title="Matrix view"
								>
									<Grid3x3 size={16} />
									Matrix
								</button>
							</div>
						</div>

						{#if permissions.length === 0 || groups.length === 0}
							<p class="text-muted">
								You need at least one permission and one group to manage visibility.
							</p>
						{:else if visibilityViewMode === 'list'}
							<div class="space-y-3">
								{#each permissions as perm}
									{@const visibleGroups = permissionVisibility[perm.key] || []}
									{@const availableGroups = getAvailableGroupsForPermission(perm.key)}
									<div class="p-4 bg-white/5 rounded border border-white/10 transition-colors hover:bg-white/10">
										<div class="flex items-start justify-between gap-4">
											<div class="flex-1">
												<div class="font-medium mb-1 text-gray-600">{perm.name}</div>
												<div class="text-xs text-muted mb-3">{perm.description}</div>
												<div class="flex flex-wrap items-center gap-2">
													{#if visibleGroups.length > 0}
														{#each visibleGroups as groupKey}
															{@const group = groups.find(g => g.key === groupKey)}
															{#if group}
																<span class="badge badge-group inline-flex items-center gap-1.5">
																	{group.name}
																	<button
																		class="hover:text-error transition-colors"
																		on:click={() => removeVisibility(perm.key, groupKey)}
																		title="Remove visibility"
																	>
																		<X size={12} />
																	</button>
																</span>
															{/if}
														{/each}
													{:else}
														<span class="text-xs text-muted italic">No groups have visibility</span>
													{/if}
													{#if availableGroups.length > 0}
														<button
															class="btn-small"
															on:click={() => openAddGroupModal(perm.key)}
															title="Add group visibility"
														>
															<Plus size={14} />
															Add Group
														</button>
													{/if}
												</div>
											</div>
										</div>
									</div>
								{/each}
							</div>
						{:else}
							<!-- Matrix View -->
							<div class="overflow-x-auto">
								<table class="table-base">
									<thead>
										<tr>
											<th class="sticky left-0 z-10 bg-input">Permission</th>
											{#each groups as group}
												<th class="text-center min-w-[120px]">{group.name}</th>
											{/each}
										</tr>
									</thead>
									<tbody>
										{#each permissions as perm}
											<tr>
												<td class="sticky left-0 z-10 bg-input">
													<div class="font-medium text-gray-600">{perm.name}</div>
													<div class="text-xs text-muted">{perm.description}</div>
												</td>
												{#each groups as group}
													{@const hasVisibility = permissionVisibility[perm.key]?.includes(group.key)}
													<td class="text-center">
														<button
															class="inline-flex items-center justify-center w-8 h-8 rounded border transition-all duration-150 ease-out hover:-translate-y-0.5 hover:shadow-md {hasVisibility ? 'border-accent bg-accent/20 text-accent' : 'border-borderc bg-input text-muted hover:border-accent/50'}"
															on:click={() => toggleVisibility(perm.key, group.key)}
															title="{hasVisibility ? 'Remove visibility' : 'Add visibility'}"
														>
															{#if hasVisibility}
																<Check size={16} />
															{:else}
																<Plus size={14} />
															{/if}
														</button>
													</td>
												{/each}
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{/if}
					</div>
				{/if}
			{/if}
		{/if}
	</div>
</div>

<!-- Permission Modal -->
{#if showPermissionModal}
	<div class="modal-overlay" on:click={closePermissionModal}>
		<div class="modal-content" on:click|stopPropagation>
			<div class="flex justify-between items-center mb-4">
				<h2 class="section-title">
					{editingPermission ? 'Edit Permission' : 'Create Permission'}
				</h2>
				<button class="text-muted hover:text-accent" on:click={closePermissionModal}>
					<X size={20} />
				</button>
			</div>
			<div class="space-y-4">
				<label class="form-label">
					<span>Name</span>
					<input
						class="input"
						type="text"
						bind:value={permissionName}
						disabled={!!editingPermission}
						placeholder="permission_name"
					/>
					{#if editingPermission}
						<p class="text-xs text-muted">Permission name cannot be changed</p>
					{/if}
				</label>
				<label class="form-label">
					<span>Definition</span>
					<textarea
						class="input"
						bind:value={permissionDefinition}
						placeholder="Description of the permission"
						rows="4"
					></textarea>
				</label>
				<div class="form-actions">
					<button class="btn-secondary" on:click={closePermissionModal}>Cancel</button>
					<button class="btn-primary" on:click={savePermission}>
						<Check size={18} />
						Save
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}

<!-- Group Modal -->
{#if showGroupModal}
	<div class="modal-overlay" on:click={closeGroupModal}>
		<div class="modal-content" on:click|stopPropagation>
			<div class="flex justify-between items-center mb-4">
				<h2 class="section-title">
					{editingGroup ? 'Edit Group' : 'Create Group'}
				</h2>
				<button class="text-muted hover:text-accent" on:click={closeGroupModal}>
					<X size={20} />
				</button>
			</div>
			<div class="space-y-4">
				<label class="form-label">
					<span>Name</span>
					<input
						class="input"
						type="text"
						bind:value={groupName}
						disabled={!!editingGroup}
						placeholder="group_name"
					/>
					{#if editingGroup}
						<p class="text-xs text-muted">Group name cannot be changed</p>
					{/if}
				</label>
				<label class="form-label">
					<span>Definition</span>
					<textarea
						class="input"
						bind:value={groupDefinition}
						placeholder="Description of the group"
						rows="4"
					></textarea>
				</label>
				<div class="form-actions">
					<button class="btn-secondary" on:click={closeGroupModal}>Cancel</button>
					<button class="btn-primary" on:click={saveGroup}>
						<Check size={18} />
						Save
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}

<!-- Add Group Visibility Modal -->
{#if showAddGroupModal && addingVisibilityForPermission}
	{@const perm = permissions.find(p => p.key === addingVisibilityForPermission)}
	{@const availableGroups = getAvailableGroupsForPermission(addingVisibilityForPermission)}
	<div class="modal-overlay" on:click={closeAddGroupModal}>
		<div class="modal-content" on:click|stopPropagation>
			<div class="flex justify-between items-center mb-4">
				<div>
					<h2 class="section-title">Add Group Visibility</h2>
					<p class="text-sm text-muted mt-1">Make "{perm?.name}" visible to a group</p>
				</div>
				<button class="text-muted hover:text-accent" on:click={closeAddGroupModal}>
					<X size={20} />
				</button>
			</div>
			<div class="space-y-4">
				<label class="form-label">
					<span>Select Group</span>
					<select class="input" bind:value={selectedGroupForAdd}>
						<option value="">Choose a group...</option>
						{#each availableGroups as grp}
							<option value={grp.key}>{grp.name}</option>
						{/each}
					</select>
				</label>
				<div class="form-actions">
					<button class="btn-secondary" on:click={closeAddGroupModal}>Cancel</button>
					<button class="btn-primary" on:click={addVisibility} disabled={!selectedGroupForAdd}>
						<Check size={18} />
						Add Visibility
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}

<!-- Delete Permission Confirmation -->
{#if deletingPermission}
	<ConfirmModal
		title="Delete Permission"
		message="Are you sure you want to delete the permission '{deletingPermission.name}'? This will also remove all visibility mappings for this permission."
		confirmText="Delete"
		cancelText="Cancel"
		on:confirm={handleDeletePermission}
		on:cancel={() => deletingPermission = null}
	/>
{/if}

<!-- Delete Group Confirmation -->
{#if deletingGroup}
	<ConfirmModal
		title="Delete Group"
		message="Are you sure you want to delete the group '{deletingGroup.name}'? This will also remove all visibility mappings for this group."
		confirmText="Delete"
		cancelText="Cancel"
		on:confirm={handleDeleteGroup}
		on:cancel={() => deletingGroup = null}
	/>
{/if}

