<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { 
		listPermissions, 
		listGroups, 
		listUsers,
		updateUser,
		createPermission, 
		updatePermission, 
		deletePermission,
		createGroup,
		updateGroup,
		deleteGroup,
		addPermissionVisibility,
		removePermissionVisibility,
		getAllPermissionVisibility,
		getAdminUserManagement
	} from '$lib/api';
	import { isSuperuser } from '$lib/stores';
	import { 
		Users, 
		Eye, 
		Plus, 
		Edit, 
		Trash2, 
		X, 
		Check,
		Grid3x3,
		List,
		Save,
		Shield,
		UserSearch,
		UserPen,
		UsersRound
	} from 'lucide-svelte';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';
	import UserKey from '$lib/components/UserKey.svelte';
	import UsersListPanel from '$lib/components/UsersListPanel.svelte';

	const SUPERUSER_TABS = new Set([
		'users',
		'permissions',
		'groups',
		'visibility',
		'admin-management'
	]);

	let activeTab = 'users';
	let loading = true;
	let accessDenied = false;
	let error = '';
	let showToast = false;
	let toastMessage = '';
	let toastType = 'success';

	// Permissions
	let permissions = [];
	let permissionSearch = '';
	let permissionName = '';
	let permissionDefinition = '';
	let originalPermissionDefinition = '';
	let editingPermission = null;
	let showPermissionModal = false;
	let showDeletePermissionConfirm = false;
	let deletingPermission = null;

	// Groups
	let groups = [];
	let groupSearch = '';
	let groupName = '';
	let groupDefinition = '';
	let originalGroupDefinition = '';
	let editingGroup = null;
	let showGroupModal = false;
	let showDeleteGroupConfirm = false;
	let deletingGroup = null;

	// Visibility - track which groups each permission is visible to
	let permissionVisibility = {}; // { permission_key: [group_key, ...] }
	let visibilityViewMode = 'list'; // 'list' or 'matrix'
	let visibilitySearch = '';
	let showRemoveVisibilityConfirm = false;
	/** @type {{ permissionKey: string, groupKey: string } | null} */
	let pendingVisibilityRemove = null;

	/** @type {{ id: string, email: string, status?: string, is_admin?: boolean, permissions?: Record<string, boolean>, groups?: Record<string, boolean> }[]} */
	let allUsers = [];
	
	// Admin-User management mappings
	let adminUserManagement = {}; // { admin_email: [user_email, ...] }
	let adminManagementSearch = '';
	let showManageableUsersModal = false;
	/** @type {{ adminEmail: string, userEmails: string[] } | null} */
	let viewingManageableUsers = null;
	let manageableUsersSearch = '';

	// Membership editing (Manage users)
	let showManageUsersModal = false;
	let showMembershipSaveConfirm = false;
	let membershipSaving = false;
	/** @type {{ type: 'permission' | 'group' | 'visibility' | 'admin-groups', name: string, key?: string, userId?: string } | null} */
	let managingMembership = null;
	/** @type {Set<string>} */
	let selectedMembers = new Set();
	/** @type {Set<string>} */
	let initialMembers = new Set();

	$: userOptions = allUsers.map((u) => ({
		key: u.id,
		name: u.email,
		description: u.status || undefined
	}));

	$: groupOptions = groups.map((g) => ({
		key: g.key,
		name: g.name,
		description: g.description || undefined
	}));

	$: groupNameOptions = groups.map((g) => ({
		key: g.name,
		name: g.name,
		description: g.description || undefined
	}));

	$: isGroupAssignment =
		managingMembership?.type === 'visibility' || managingMembership?.type === 'admin-groups';

	$: assignmentOptions = isGroupAssignment
		? managingMembership?.type === 'visibility'
			? groupOptions
			: groupNameOptions
		: userOptions;

	$: assignmentLabel = isGroupAssignment ? 'Groups' : 'Users';
	$: assignmentPlaceholder = isGroupAssignment ? 'Search groups to add…' : 'Search users to add…';
	$: assignmentHelp = isGroupAssignment
		? 'Search to add groups. Selected groups appear as chips — remove with ×. Newly added chips are yellow with +; removed ones stay yellow with − until you restore them or save.'
		: 'Search to add users. Selected users appear as chips — remove with ×. Newly added chips are yellow with +; removed ones stay yellow with − until you restore them or save.';

	$: permissionUserCounts = (() => {
		/** @type {Record<string, number>} */
		const counts = {};
		for (const user of allUsers) {
			for (const [perm, enabled] of Object.entries(user.permissions || {})) {
				if (!enabled) continue;
				counts[perm] = (counts[perm] || 0) + 1;
			}
		}
		return counts;
	})();

	$: groupUserCounts = (() => {
		/** @type {Record<string, number>} */
		const counts = {};
		for (const user of allUsers) {
			for (const [group, enabled] of Object.entries(user.groups || {})) {
				if (!enabled) continue;
				counts[group] = (counts[group] || 0) + 1;
			}
		}
		return counts;
	})();

	$: filteredPermissions = (() => {
		const q = permissionSearch.trim().toLowerCase();
		if (!q) return permissions;
		return permissions.filter(
			(p) =>
				(p.name || '').toLowerCase().includes(q) ||
				(p.description || '').toLowerCase().includes(q)
		);
	})();

	$: filteredGroups = (() => {
		const q = groupSearch.trim().toLowerCase();
		if (!q) return groups;
		return groups.filter(
			(g) =>
				(g.name || '').toLowerCase().includes(q) ||
				(g.description || '').toLowerCase().includes(q)
		);
	})();

	$: filteredVisibilityPermissions = (() => {
		const q = visibilitySearch.trim().toLowerCase();
		if (!q) return permissions;
		return permissions.filter((p) => {
			if ((p.name || '').toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q)) {
				return true;
			}
			const visibleKeys = permissionVisibility[p.key] || [];
			return visibleKeys.some((groupKey) => {
				const group = groups.find((g) => g.key === groupKey);
				return (group?.name || '').toLowerCase().includes(q);
			});
		});
	})();

	$: adminManagementRows = (() => {
		/** @type {Map<string, string[]>} */
		const byEmail = new Map();
		for (const [adminEmail, userEmails] of Object.entries(adminUserManagement)) {
			byEmail.set(adminEmail, Array.isArray(userEmails) ? userEmails : []);
		}
		for (const user of allUsers) {
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

	$: filteredManageableUserEmails = (() => {
		if (!viewingManageableUsers) return [];
		const q = manageableUsersSearch.trim().toLowerCase();
		const emails = viewingManageableUsers.userEmails;
		if (!q) return emails;
		return emails.filter((email) => String(email).toLowerCase().includes(q));
	})();

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

	$: memberAdds = [...selectedMembers].filter((id) => !initialMembers.has(id));
	$: memberRemoves = [...initialMembers].filter((id) => !selectedMembers.has(id));
	$: memberChangeItems = [
		...memberAdds.map((id) => ({
			label: assignmentLabelForKey(id),
			kind: 'add',
			target: isGroupAssignment ? 'group' : 'user',
			key: id
		})),
		...memberRemoves.map((id) => ({
			label: assignmentLabelForKey(id),
			kind: 'remove',
			target: isGroupAssignment ? 'group' : 'user',
			key: id
		}))
	];
	$: membershipDirty = memberChangeItems.length > 0;
	$: manageSubjectLabel =
		managingMembership?.type === 'visibility'
			? 'visibility of permission'
			: managingMembership?.type === 'admin-groups'
				? 'groups of admin'
				: managingMembership?.type === 'permission'
					? 'permission'
					: 'group';
	$: membershipSaveMessage = managingMembership
		? `Save changes for ${manageSubjectLabel} "${managingMembership.name}"?\n\n${memberChangeItems
				.map((i) => `• ${i.kind === 'add' ? 'Add' : 'Remove'}: ${i.label}`)
				.join('\n')}`
		: '';
	$: manageUsersTitle = managingMembership
		? managingMembership.type === 'permission'
			? `Manage users for permission: ${managingMembership.name}`
			: managingMembership.type === 'group'
				? `Manage users for group: ${managingMembership.name}`
				: managingMembership.type === 'visibility'
					? `Manage visibility for permission: ${managingMembership.name}`
					: `Manage groups for admin: ${managingMembership.name}`
		: 'Manage assignment';

	function assignmentLabelForKey(/** @type {string} */ key) {
		if (isGroupAssignment) {
			const fromOpts = assignmentOptions.find((o) => o.key === key);
			return fromOpts?.name || key;
		}
		return userEmail(key);
	}

	onMount(async () => {
		const tab = $page.url.searchParams.get('tab');
		if (tab && SUPERUSER_TABS.has(tab)) {
			activeTab = tab;
		}
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

	function setActiveTab(/** @type {string} */ tab) {
		activeTab = tab;
		goto(`/superuser?tab=${tab}`, { replaceState: true, keepFocus: true, noScroll: true });
	}

	async function loadData() {
		const [perms, grps] = await Promise.all([
			listPermissions().catch(() => []),
			listGroups().catch(() => [])
		]);
		permissions = perms || [];
		groups = grps || [];
		await Promise.all([
			loadVisibilityMappings(),
			loadAllUsers(),
			loadAdminUserManagement()
		]);
	}

	function enabledKeys(/** @type {Record<string, boolean> | undefined} */ map) {
		return Object.fromEntries(Object.entries(map || {}).filter(([, enabled]) => enabled));
	}

	function userEmail(/** @type {string} */ id) {
		return allUsers.find((u) => u.id === id)?.email || id;
	}

	async function loadAllUsers() {
		try {
			const res = await listUsers();
			allUsers = res.users || [];
		} catch (e) {
			allUsers = [];
		}
	}

	function openManagePermissionUsers(perm) {
		managingMembership = { type: 'permission', name: perm.name };
		const members = new Set(
			allUsers.filter((u) => u.permissions?.[perm.name]).map((u) => u.id)
		);
		initialMembers = new Set(members);
		selectedMembers = new Set(members);
		showManageUsersModal = true;
	}

	function openManageGroupUsers(grp) {
		managingMembership = { type: 'group', name: grp.name };
		const members = new Set(allUsers.filter((u) => u.groups?.[grp.name]).map((u) => u.id));
		initialMembers = new Set(members);
		selectedMembers = new Set(members);
		showManageUsersModal = true;
	}

	function openManageVisibilityGroups(perm) {
		managingMembership = { type: 'visibility', name: perm.name, key: perm.key };
		const members = new Set(permissionVisibility[perm.key] || []);
		initialMembers = new Set(members);
		selectedMembers = new Set(members);
		showManageUsersModal = true;
	}

	function openManageAdminGroups(adminEmail) {
		const admin = allUsers.find((u) => u.email === adminEmail);
		if (!admin) {
			showToastMessage('Admin user not found in user list', 'error');
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
			showToastMessage('No changes to save', 'error');
			return;
		}
		showMembershipSaveConfirm = true;
	}

	async function saveUserMembership(targetType, targetName, adds, removes) {
		let failed = 0;
		let lastError = '';
		for (const id of adds) {
			const user = allUsers.find((u) => u.id === id);
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
			const user = allUsers.find((u) => u.id === id);
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
		allUsers = [...allUsers];
		return { failed, lastError };
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

	async function saveAdminGroupsAssignment(userId, adds, removes) {
		const user = allUsers.find((u) => u.id === userId);
		if (!user) return { failed: 1, lastError: 'Admin user not found' };
		const groupsMap = { ...enabledKeys(user.groups) };
		for (const groupName of adds) groupsMap[groupName] = true;
		for (const groupName of removes) delete groupsMap[groupName];
		try {
			await updateUser(userId, { groups: groupsMap });
			user.groups = groupsMap;
			allUsers = [...allUsers];
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
		const targetType = managingMembership.type;
		const adds = [...memberAdds];
		const removes = [...memberRemoves];

		try {
			let failed = 0;
			let lastError = '';

			if (targetType === 'visibility') {
				const permKey = managingMembership.key || targetName;
				({ failed, lastError } = await saveVisibilityAssignment(
					permKey,
					targetName,
					adds,
					removes
				));
			} else if (targetType === 'admin-groups') {
				({ failed, lastError } = await saveAdminGroupsAssignment(
					managingMembership.userId || '',
					adds,
					removes
				));
			} else {
				({ failed, lastError } = await saveUserMembership(
					targetType,
					targetName,
					adds,
					removes
				));
			}

			if (failed > 0) {
				showToastMessage(
					`Updated with ${failed} failure(s)${lastError ? `: ${lastError}` : ''}`,
					'error'
				);
				if (targetType === 'visibility') {
					await loadVisibilityMappings();
					if (managingMembership?.key) {
						const members = new Set(permissionVisibility[managingMembership.key] || []);
						initialMembers = new Set(members);
						selectedMembers = new Set(members);
					}
				} else if (targetType === 'admin-groups') {
					await loadAllUsers();
					await loadAdminUserManagement();
					const admin = allUsers.find((u) => u.id === managingMembership?.userId);
					const members = new Set(
						Object.entries(admin?.groups || {})
							.filter(([, enabled]) => enabled)
							.map(([groupName]) => groupName)
					);
					initialMembers = new Set(members);
					selectedMembers = new Set(members);
				} else {
					await loadAllUsers();
					if (managingMembership) {
						const name = managingMembership.name;
						const members = new Set(
							allUsers
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
				}
			} else {
				const parts = [];
				if (adds.length) parts.push(`+${adds.length}`);
				if (removes.length) parts.push(`−${removes.length}`);
				const noun =
					targetType === 'visibility' || targetType === 'admin-groups' ? 'groups' : 'members';
				showToastMessage(
					`Updated ${manageSubjectLabel} "${targetName}" ${noun} (${parts.join(', ')})`,
					'success'
				);
				closeManageUsersModal();
			}
		} finally {
			membershipSaving = false;
		}
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

	$: permissionDirty = editingPermission
		? permissionDefinition.trim() !== originalPermissionDefinition.trim()
		: permissionName.trim().length > 0 && permissionDefinition.trim().length > 0;
	$: groupDirty = editingGroup
		? groupDefinition.trim() !== originalGroupDefinition.trim()
		: groupName.trim().length > 0 && groupDefinition.trim().length > 0;

	function showToastMessage(message, type = 'success') {
		toastMessage = message;
		toastType = type;
		showToast = true;
		setTimeout(() => {
			showToast = false;
		}, 5000);
	}

	// Permission functions
	function openPermissionModal(perm = null) {
		editingPermission = perm;
		if (perm) {
			permissionName = perm.key;
			permissionDefinition = perm.description || '';
			originalPermissionDefinition = perm.description || '';
		} else {
			permissionName = '';
			permissionDefinition = '';
			originalPermissionDefinition = '';
		}
		showPermissionModal = true;
	}

	function closePermissionModal() {
		showPermissionModal = false;
		editingPermission = null;
		permissionName = '';
		permissionDefinition = '';
		originalPermissionDefinition = '';
	}

	async function savePermission() {
		if (!permissionName.trim() || !permissionDefinition.trim()) {
			showToastMessage('Name and definition are required', 'error');
			return;
		}
		if (editingPermission && !permissionDirty) {
			showToastMessage('No changes to save', 'error');
			return;
		}
		try {
			if (editingPermission) {
				await updatePermission(editingPermission.key, permissionDefinition);
				showToastMessage(`Updated permission "${editingPermission.name}"`, 'success');
			} else {
				await createPermission(permissionName.trim(), permissionDefinition.trim());
				showToastMessage(`Created permission "${permissionName.trim()}"`, 'success');
			}
			await loadData();
			closePermissionModal();
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Failed to save permission', 'error');
		}
	}

	function requestDeletePermission(perm) {
		deletingPermission = perm;
		showDeletePermissionConfirm = true;
	}

	async function handleDeletePermission() {
		if (!deletingPermission) return;
		try {
			const name = deletingPermission.name;
			await deletePermission(deletingPermission.key);
			await loadData();
			deletingPermission = null;
			showDeletePermissionConfirm = false;
			showToastMessage(`Deleted permission "${name}"`, 'success');
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Failed to delete permission', 'error');
		}
	}

	// Group functions
	function openGroupModal(grp = null) {
		editingGroup = grp;
		if (grp) {
			groupName = grp.key;
			groupDefinition = grp.description || '';
			originalGroupDefinition = grp.description || '';
		} else {
			groupName = '';
			groupDefinition = '';
			originalGroupDefinition = '';
		}
		showGroupModal = true;
	}

	function closeGroupModal() {
		showGroupModal = false;
		editingGroup = null;
		groupName = '';
		groupDefinition = '';
		originalGroupDefinition = '';
	}

	async function saveGroup() {
		if (!groupName.trim() || !groupDefinition.trim()) {
			showToastMessage('Name and definition are required', 'error');
			return;
		}
		if (editingGroup && !groupDirty) {
			showToastMessage('No changes to save', 'error');
			return;
		}
		try {
			if (editingGroup) {
				await updateGroup(editingGroup.key, groupDefinition.trim());
				showToastMessage(`Updated group "${editingGroup.name}"`, 'success');
			} else {
				await createGroup(groupName.trim(), groupDefinition.trim());
				showToastMessage(`Created group "${groupName.trim()}"`, 'success');
			}
			await loadData();
			closeGroupModal();
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Failed to save group', 'error');
		}
	}

	function requestDeleteGroup(grp) {
		deletingGroup = grp;
		showDeleteGroupConfirm = true;
	}

	async function handleDeleteGroup() {
		if (!deletingGroup) return;
		try {
			const name = deletingGroup.name;
			await deleteGroup(deletingGroup.key);
			await loadData();
			deletingGroup = null;
			showDeleteGroupConfirm = false;
			showToastMessage(`Deleted group "${name}"`, 'success');
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Failed to delete group', 'error');
		}
	}

	// Visibility functions
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
			showToastMessage(`Visibility: "${permName}" → "${groupNameLabel}" removed`, 'success');
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Failed to remove visibility mapping', 'error');
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
				permissionVisibility[permissionKey] = [...permissionVisibility[permissionKey], groupKey];
			}
			showToastMessage(`Visibility: "${permName}" → "${groupNameLabel}" added`, 'success');
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'Failed to add visibility mapping';
			if (!msg.includes('already exists') && !msg.includes('duplicate')) {
				showToastMessage(msg, 'error');
			} else {
				if (!permissionVisibility[permissionKey]) {
					permissionVisibility[permissionKey] = [];
				}
				if (!permissionVisibility[permissionKey].includes(groupKey)) {
					permissionVisibility[permissionKey] = [...permissionVisibility[permissionKey], groupKey];
				}
				showToastMessage(`Visibility: "${permName}" → "${groupNameLabel}" added`, 'success');
			}
		}
	}

	$: removeVisibilityMessage = (() => {
		const pending = pendingVisibilityRemove;
		if (!pending) return 'Remove this visibility mapping?';
		const permName =
			permissions.find((p) => p.key === pending.permissionKey)?.name || pending.permissionKey;
		const groupName = groups.find((g) => g.key === pending.groupKey)?.name || pending.groupKey;
		return `Remove visibility of "${permName}" from "${groupName}"?`;
	})();

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
			<a href="/dashboard" class="btn-secondary">Back to Dashboard</a>
		{:else}
			<div class="flex items-start justify-between gap-3">
				<div>
					<h1 class="page-title">Superuser</h1>
					<p class="section-subtitle">
						Manage all users, permissions, groups, visibility, and admin scope
					</p>
				</div>
			</div>

			{#if error}
				<div class="error">{error}</div>
			{/if}

			{#if loading}
				<p class="text-muted">Loading...</p>
			{:else}
				<!-- Tabs -->
				<div class="flex gap-2 border-b border-borderc flex-wrap">
					<button
						type="button"
						class="px-4 py-2 font-medium transition-colors {activeTab === 'users' ? 'text-accent border-b-2 border-accent' : 'text-muted hover:text-accent'}"
						on:click={() => setActiveTab('users')}
					>
						<Users size={18} class="inline mr-2" />
						Users
					</button>
					<button
						type="button"
						class="px-4 py-2 font-medium transition-colors {activeTab === 'permissions' ? 'text-accent border-b-2 border-accent' : 'text-muted hover:text-accent'}"
						on:click={() => setActiveTab('permissions')}
					>
						<UserKey size={18} class="inline mr-2" />
						Permissions
					</button>
					<button
						type="button"
						class="px-4 py-2 font-medium transition-colors {activeTab === 'groups' ? 'text-accent border-b-2 border-accent' : 'text-muted hover:text-accent'}"
						on:click={() => setActiveTab('groups')}
					>
						<UsersRound size={18} class="inline mr-2" />
						Groups
					</button>
					<button
						type="button"
						class="px-4 py-2 font-medium transition-colors {activeTab === 'visibility' ? 'text-accent border-b-2 border-accent' : 'text-muted hover:text-accent'}"
						on:click={() => setActiveTab('visibility')}
					>
						<Eye size={18} class="inline mr-2" />
						Permission Visibility
					</button>
					<button
						type="button"
						class="px-4 py-2 font-medium transition-colors {activeTab === 'admin-management' ? 'text-accent border-b-2 border-accent' : 'text-muted hover:text-accent'}"
						on:click={() => setActiveTab('admin-management')}
					>
						<Shield size={18} class="inline mr-2" />
						Admin-User Management
					</button>
				</div>

				{#if activeTab === 'users'}
					<div class="space-y-4">
						<div>
							<h2 class="section-title">Users</h2>
							<p class="text-sm text-muted mt-1">
								View and manage every user account in the system.
							</p>
						</div>
						<UsersListPanel detailBase="/admin/users" />
					</div>
				{/if}

				<!-- Permissions Tab -->
				{#if activeTab === 'permissions'}
					<div class="space-y-4">
						<div class="flex justify-between items-center gap-3 flex-wrap">
							<div>
								<h2 class="section-title">Permissions</h2>
								<p class="text-sm text-muted mt-1">
									Create and edit permissions, and assign users to each permission.
								</p>
							</div>
							<button class="btn-light py-1.5 text-xs" on:click={() => openPermissionModal()}>
								<Plus size={16} class="-ml-0.5" />
								Create Permission
							</button>
						</div>

						<label class="form-label max-w-md">
							<span>Search</span>
							<input
								class="input"
								type="search"
								placeholder="Search by name or description..."
								bind:value={permissionSearch}
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
								{#if permissions.length === 0}
									<tr>
										<td colspan="4" class="text-center text-muted py-4">No permissions found.</td>
									</tr>
								{:else if filteredPermissions.length === 0}
									<tr>
										<td colspan="4" class="text-center text-muted py-4">
											No permissions match your search.
										</td>
									</tr>
								{:else}
									{#each filteredPermissions as perm}
										<tr>
											<td class="font-medium whitespace-nowrap">{perm.name}</td>
											<td class="text-muted max-w-md truncate" title={perm.description || ''}>
												{perm.description || '—'}
											</td>
											<td>{permissionUserCounts[perm.name] || 0}</td>
											<td>
												<div class="flex flex-nowrap gap-0.5">
													<button
														class="btn-icon"
														type="button"
														title="Manage users"
														aria-label="Manage users for permission {perm.name}"
														on:click={() => openManagePermissionUsers(perm)}
													>
														<Users size={20} />
													</button>
													<button
														class="btn-icon"
														type="button"
														title="Edit permission"
														aria-label="Edit permission {perm.name}"
														on:click={() => openPermissionModal(perm)}
													>
														<Edit size={20} />
													</button>
													<button
														class="btn-icon-danger"
														type="button"
														title="Delete permission"
														aria-label="Delete permission {perm.name}"
														on:click={() => requestDeletePermission(perm)}
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
				{/if}

				<!-- Groups Tab -->
				{#if activeTab === 'groups'}
					<div class="space-y-4">
						<div class="flex justify-between items-center gap-3 flex-wrap">
							<div>
								<h2 class="section-title">Groups</h2>
								<p class="text-sm text-muted mt-1">
									Create and edit groups, and assign users to each group.
								</p>
							</div>
							<button class="btn-light py-1.5 text-xs" on:click={() => openGroupModal()}>
								<Plus size={16} class="-ml-0.5" />
								Create Group
							</button>
						</div>

						<label class="form-label max-w-md">
							<span>Search</span>
							<input
								class="input"
								type="search"
								placeholder="Search by name or description..."
								bind:value={groupSearch}
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
								{#if groups.length === 0}
									<tr>
										<td colspan="4" class="text-center text-muted py-4">No groups found.</td>
									</tr>
								{:else if filteredGroups.length === 0}
									<tr>
										<td colspan="4" class="text-center text-muted py-4">
											No groups match your search.
										</td>
									</tr>
								{:else}
									{#each filteredGroups as grp}
										<tr>
											<td class="font-medium whitespace-nowrap">{grp.name}</td>
											<td class="text-muted max-w-md truncate" title={grp.description || ''}>
												{grp.description || '—'}
											</td>
											<td>{groupUserCounts[grp.name] || 0}</td>
											<td>
												<div class="flex flex-nowrap gap-0.5">
													<button
														class="btn-icon"
														type="button"
														title="Manage users"
														aria-label="Manage users for group {grp.name}"
														on:click={() => openManageGroupUsers(grp)}
													>
														<Users size={20} />
													</button>
													<button
														class="btn-icon"
														type="button"
														title="Edit group"
														aria-label="Edit group {grp.name}"
														on:click={() => openGroupModal(grp)}
													>
														<Edit size={20} />
													</button>
													<button
														class="btn-icon-danger"
														type="button"
														title="Delete group"
														aria-label="Delete group {grp.name}"
														on:click={() => requestDeleteGroup(grp)}
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
				{/if}

				<!-- Admin-User Management Tab -->
				{#if activeTab === 'admin-management'}
					<div class="space-y-4">
						<div>
							<h2 class="section-title">Admin-User Management</h2>
							<p class="text-sm text-muted mt-1">
								See which admins can manage which users (based on shared groups).
							</p>
						</div>

						<label class="form-label max-w-md">
							<span>Search</span>
							<input
								class="input"
								type="search"
								placeholder="Search by admin or user email..."
								bind:value={adminManagementSearch}
							/>
						</label>

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
										<td colspan="3" class="text-center text-muted py-4">
											No admin-user management relationships found.
										</td>
									</tr>
								{:else if filteredAdminManagementRows.length === 0}
									<tr>
										<td colspan="3" class="text-center text-muted py-4">
											No admins match your search.
										</td>
									</tr>
								{:else}
									{#each filteredAdminManagementRows as row}
										<tr>
											<td class="font-medium whitespace-nowrap">{row.adminEmail}</td>
											<td class="tabular-nums">{row.userEmails.length}</td>
											<td>
												<div class="flex flex-nowrap gap-0.5">
													<button
														class="btn-icon"
														type="button"
														title="View manageable users"
														aria-label="View manageable users for admin {row.adminEmail}"
														on:click={() => openManageableUsersModal(row)}
													>
														<UserSearch size={20} />
													</button>
													<button
														class="btn-icon"
														type="button"
														title="Manage groups of the admin"
														aria-label="Manage groups of the admin {row.adminEmail}"
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
				{/if}

				{#if activeTab === 'visibility'}
					<div class="space-y-4">
						<div class="flex justify-between items-center gap-3 flex-wrap">
							<div>
								<h2 class="section-title">Permission Visibility</h2>
								<p class="text-sm text-muted mt-1">
									Manage which groups can see and manage each permission.
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

						{#if permissions.length === 0 || groups.length === 0}
							<p class="text-muted">
								You need at least one permission and one group to manage visibility.
							</p>
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
											{#each filteredVisibilityPermissions as perm}
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
							{:else}
								<div class="overflow-x-auto">
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
													<td
														colspan={groups.length + 1}
														class="text-center text-muted py-4"
													>
														No permissions match your search.
													</td>
												</tr>
											{:else}
												{#each filteredVisibilityPermissions as perm}
													<tr>
														<td class="sticky left-0 z-10 bg-input">
															<div class="font-medium text-gray-600">{perm.name}</div>
															<div class="text-xs text-muted">{perm.description}</div>
														</td>
														{#each groups as group}
															{@const hasVisibility = permissionVisibility[perm.key]?.includes(
																group.key
															)}
															<td class="p-2 text-center align-middle">
																<button
																	type="button"
																	class="mx-auto flex h-6 w-6 items-center justify-center border-0 bg-transparent p-0 transition-transform duration-150 ease-out hover:-translate-y-0.5 motion-reduce:transition-none motion-reduce:hover:translate-y-0 {hasVisibility
																		? 'text-accent'
																		: 'text-muted opacity-35'}"
																	on:click={() => toggleVisibility(perm.key, group.key)}
																	title={hasVisibility
																		? 'Remove visibility'
																		: 'Add visibility'}
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
						{/if}
					</div>
				{/if}
			{/if}
		{/if}
	</div>
</div>

<!-- Permission Modal -->
<Modal
	bind:open={showPermissionModal}
	title={editingPermission ? 'Edit Permission' : 'Create Permission'}
	labelledBy="perm-modal-title"
	on:close={closePermissionModal}
>
	<button slot="header-end" type="button" class="text-muted hover:text-accent" on:click={closePermissionModal} aria-label="Close">
		<X size={20} />
	</button>
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
		{#if editingPermission && permissionDirty}
			<p class="text-sm text-muted">Definition changed — save to apply.</p>
		{/if}
		<div class="form-actions">
			<button type="button" class="btn-secondary" on:click={closePermissionModal}>Cancel</button>
			<button type="button" class="btn-primary" on:click={savePermission} disabled={!permissionDirty}>
				<Check size={18} class="-ml-0.5" />
				{editingPermission ? (permissionDirty ? 'Save Changes' : 'No changes') : 'Create'}
			</button>
		</div>
	</div>
</Modal>

<!-- Group Modal -->
<Modal
	bind:open={showGroupModal}
	title={editingGroup ? 'Edit Group' : 'Create Group'}
	labelledBy="group-modal-title"
	on:close={closeGroupModal}
>
	<button slot="header-end" type="button" class="text-muted hover:text-accent" on:click={closeGroupModal} aria-label="Close">
		<X size={20} />
	</button>
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
		{#if editingGroup && groupDirty}
			<p class="text-sm text-muted">Definition changed — save to apply.</p>
		{/if}
		<div class="form-actions">
			<button type="button" class="btn-secondary" on:click={closeGroupModal}>Cancel</button>
			<button type="button" class="btn-primary" on:click={saveGroup} disabled={!groupDirty}>
				<Check size={18} class="-ml-0.5" />
				{editingGroup ? (groupDirty ? 'Save Changes' : 'No changes') : 'Create'}
			</button>
		</div>
	</div>
</Modal>

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

<ConfirmModal
	bind:open={showDeletePermissionConfirm}
	title="Delete Permission"
	message={deletingPermission
		? `Delete permission "${deletingPermission.name}"? This also removes all visibility mappings for it.`
		: 'Delete this permission?'}
	confirmText="Delete"
	cancelText="Cancel"
	confirmClass="btn-danger"
	on:confirm={handleDeletePermission}
	on:cancel={() => {
		deletingPermission = null;
	}}
/>

<ConfirmModal
	bind:open={showDeleteGroupConfirm}
	title="Delete Group"
	message={deletingGroup
		? `Delete group "${deletingGroup.name}"? This also removes all visibility mappings for it.`
		: 'Delete this group?'}
	confirmText="Delete"
	cancelText="Cancel"
	confirmClass="btn-danger"
	on:confirm={handleDeleteGroup}
	on:cancel={() => {
		deletingGroup = null;
	}}
/>

<!-- Manageable users (read-only) -->
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
		<div class="space-y-4">
			<p class="text-sm text-muted -mt-2">
				{viewingManageableUsers.userEmails.length} user{viewingManageableUsers.userEmails.length === 1
					? ''
					: 's'} this admin can manage (via shared groups).
			</p>
			{#if viewingManageableUsers.userEmails.length > 0}
				<label class="form-label">
					<span>Search</span>
					<input
						class="input"
						type="search"
						placeholder="Filter by email..."
						bind:value={manageableUsersSearch}
					/>
				</label>
				{#if filteredManageableUserEmails.length === 0}
					<p class="text-sm text-muted">No users match your search.</p>
				{:else}
					<ul class="max-h-80 overflow-y-auto divide-y divide-borderc rounded-md border border-borderc">
						{#each filteredManageableUserEmails as email}
							<li class="px-3 py-2 text-sm text-gray-600">{email}</li>
						{/each}
					</ul>
				{/if}
			{:else}
				<p class="text-sm text-muted">This admin cannot manage any users yet.</p>
			{/if}
			<div class="form-actions">
				<button type="button" class="btn-secondary" on:click={closeManageableUsersModal}>Close</button>
			</div>
		</div>
	{/if}
</Modal>

<!-- Manage assignment (users or groups) -->
<Modal
	bind:open={showManageUsersModal}
	title={manageUsersTitle}
	labelledBy="manage-users-title"
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
				{assignmentHelp}
			</p>
			{#if assignmentOptions.length === 0}
				<p class="text-sm text-muted">No {assignmentLabel.toLowerCase()} available.</p>
			{:else}
				<MultiSelectChips
					options={assignmentOptions}
					bind:selected={selectedMembers}
					initial={initialMembers}
					variant={isGroupAssignment || managingMembership.type === 'group' ? 'group' : 'permission'}
					placeholder={assignmentPlaceholder}
					label={assignmentLabel}
				/>
			{/if}
			<ChangeSummary
				title="Pending save"
				items={memberChangeItems}
				emptyText="No unsaved changes."
				on:revert={revertMemberChange}
			/>
			<div class="form-actions">
				<button type="button" class="btn-secondary" on:click={closeManageUsersModal} disabled={membershipSaving}
					>Cancel</button
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
	title="Confirm changes"
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

