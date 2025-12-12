<script>
	import { onMount } from 'svelte';
	import { requestUpdate, listPermissions, listGroups } from '$lib/api';
	import { goto } from '$app/navigation';
	import { user } from '$lib/stores';
	import { ArrowLeft, Send } from 'lucide-svelte';
	let error = '';
	let success = '';
	let loading = false;
	let showToast = false;
	let toastMessage = '';
	let toastType = 'success';

	let availablePermissions = [];
	let availableGroups = [];
	let selectedPermissions = new Set();
	let selectedGroups = new Set();
	let initialPermissions = new Set(); // Track initial state
	let initialGroups = new Set(); // Track initial state
	
	// Search filters
	let permissionSearch = '';
	let groupSearch = '';

	onMount(async () => {
		try {
			const [perms, grps] = await Promise.all([listPermissions().catch(() => []), listGroups().catch(() => [])]);
			availablePermissions = perms || [];
			availableGroups = grps || [];
			
			// Pre-select permissions and groups the user already has
			if ($user?.permissions) {
				Object.entries($user.permissions).forEach(([key, enabled]) => {
					if (enabled) {
						selectedPermissions.add(key);
						initialPermissions.add(key);
					}
				});
				selectedPermissions = new Set(selectedPermissions);
				initialPermissions = new Set(initialPermissions);
			}
			
			if ($user?.groups) {
				Object.entries($user.groups).forEach(([key, member]) => {
					if (member) {
						selectedGroups.add(key);
						initialGroups.add(key);
					}
				});
				selectedGroups = new Set(selectedGroups);
				initialGroups = new Set(initialGroups);
			}
		} catch (e) {
			console.error(e);
		}
	});

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


	async function handleSubmit() {
		
		// Compute add/remove lists by comparing current selection with initial state
		const permissionsAdd = [];
		const permissionsRemove = [];
		const groupsAdd = [];
		const groupsRemove = [];

		// Find permissions to add (in selected but not in initial)
		selectedPermissions.forEach((perm) => {
			if (!initialPermissions.has(perm)) {
				permissionsAdd.push(perm);
			}
		});

		// Find permissions to remove (in initial but not in selected)
		initialPermissions.forEach((perm) => {
			if (!selectedPermissions.has(perm)) {
				permissionsRemove.push(perm);
			}
		});

		// Find groups to add (in selected but not in initial)
		selectedGroups.forEach((group) => {
			if (!initialGroups.has(group)) {
				groupsAdd.push(group);
			}
		});

		// Find groups to remove (in initial but not in selected)
		initialGroups.forEach((group) => {
			if (!selectedGroups.has(group)) {
				groupsRemove.push(group);
			}
		});

		// Check if there are any changes
		if (permissionsAdd.length === 0 && permissionsRemove.length === 0 &&
			groupsAdd.length === 0 && groupsRemove.length === 0) {
			showToastMessage('No changes to request', 'error');
			return;
		}

		loading = true;
		try {
			await requestUpdate({
				permissions_add: permissionsAdd.length > 0 ? permissionsAdd : undefined,
				permissions_remove: permissionsRemove.length > 0 ? permissionsRemove : undefined,
				groups_add: groupsAdd.length > 0 ? groupsAdd : undefined,
				groups_remove: groupsRemove.length > 0 ? groupsRemove : undefined
			});
			showToastMessage('Update request submitted!', 'success');
			setTimeout(() => goto('/dashboard'), 2000);
		} catch (e) {
			showToastMessage(e instanceof Error ? e.message : 'Request failed', 'error');
		}
		loading = false;
	}

	function showToastMessage(message, type = 'success') {
		toastMessage = message;
		toastType = type;
		showToast = true;
		setTimeout(() => {
			showToast = false;
		}, 3000);
	}
</script>

<svelte:head>
	<title>Request Update | garde</title>
</svelte:head>

<div class="container-medium">
	<div class="card space-y-4">
		<div class="flex items-start justify-between gap-3">
			<div>
				<h1 class="page-title">Request Update</h1>
				<p class="section-subtitle">
					Request permission or group changes from an admin.
				</p>
			</div>
			<a href="/dashboard" class="w-full sm:w-auto sm:ml-auto">
				<button class="btn-secondary w-full sm:w-auto"><ArrowLeft size={18} />Back to Dashboard</button>
			</a>
		</div>

		<div class="pill-card space-y-3">
			<h2 class="section-title">Permissions</h2>
			{#if (availablePermissions || []).length === 0}
				<p class="text-muted text-sm">No permissions available.</p>
			{:else}
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
							class="chip-selectable {selectedPermissions.has(perm.key) ? 'chip-selected chip-permission' : 'chip-unselected'}"
							on:click={() => togglePermission(perm.key)}
							title={perm.description}
						>
							{#if selectedPermissions.has(perm.key)}
								<span class="chip-check">✓</span>
							{/if}
							{perm.name}
						</button>
					{/each}
				</div>
			{/if}
		</div>

		<div class="pill-card space-y-3">
			<h2 class="section-title">Groups</h2>
			{#if (availableGroups || []).length === 0}
				<p class="text-muted text-sm">No groups available.</p>
			{:else}
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
							class="chip-selectable {selectedGroups.has(group.key) ? 'chip-selected chip-group' : 'chip-unselected'}"
							on:click={() => toggleGroup(group.key)}
							title={group.description}
						>
							{#if selectedGroups.has(group.key)}
								<span class="chip-check">✓</span>
							{/if}
							{group.name}
						</button>
					{/each}
				</div>
			{/if}
		</div>


		<div class="flex justify-center">
			<button class="btn-secondary w-full sm:w-auto" type="button" on:click={handleSubmit} disabled={loading}>
				<Send size={18} />
				{loading ? 'Submitting...' : 'Submit Request'}
			</button>
		</div>
	</div>
</div>

{#if showToast}
	<div class="toast" class:toast-success={toastType === 'success'} class:toast-error={toastType === 'error'}>
		{toastMessage}
	</div>
{/if}

