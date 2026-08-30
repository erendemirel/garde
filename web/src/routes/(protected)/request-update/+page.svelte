<script>
	import { onMount } from 'svelte';
	import { requestUpdate, listPermissions, listGroups } from '$lib/api';
	import { goto } from '$app/navigation';
	import { user } from '$lib/stores';
	import { ArrowLeft, Send } from 'lucide-svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';

	let loading = false;
	let showToast = false;
	let toastMessage = '';
	let toastType = 'success';

	let availablePermissions = [];
	let availableGroups = [];
	let selectedPermissions = new Set();
	let selectedGroups = new Set();
	let initialPermissions = new Set();
	let initialGroups = new Set();

	let permissionSearch = '';
	let groupSearch = '';

	$: permissionsAdd = [...selectedPermissions].filter((p) => !initialPermissions.has(p));
	$: permissionsRemove = [...initialPermissions].filter((p) => !selectedPermissions.has(p));
	$: groupsAdd = [...selectedGroups].filter((g) => !initialGroups.has(g));
	$: groupsRemove = [...initialGroups].filter((g) => !selectedGroups.has(g));
	$: changeItems = [
		...permissionsAdd.map((p) => ({
			label: availablePermissions.find((x) => x.key === p)?.name || p,
			kind: 'add',
			target: 'permission',
			key: p
		})),
		...permissionsRemove.map((p) => ({
			label: availablePermissions.find((x) => x.key === p)?.name || p,
			kind: 'remove',
			target: 'permission',
			key: p
		})),
		...groupsAdd.map((g) => ({
			label: availableGroups.find((x) => x.key === g)?.name || g,
			kind: 'add',
			target: 'group',
			key: g
		})),
		...groupsRemove.map((g) => ({
			label: availableGroups.find((x) => x.key === g)?.name || g,
			kind: 'remove',
			target: 'group',
			key: g
		}))
	];
	$: hasChanges = changeItems.length > 0;

	function chipClass(selected, initial) {
		if (selected && !initial) return 'chip-selectable chip-added';
		if (!selected && initial) return 'chip-selectable chip-removed';
		if (selected) return 'chip-selectable chip-selected chip-permission';
		return 'chip-selectable chip-unselected';
	}

	function groupChipClass(selected, initial) {
		if (selected && !initial) return 'chip-selectable chip-added';
		if (!selected && initial) return 'chip-selectable chip-removed';
		if (selected) return 'chip-selectable chip-selected chip-group';
		return 'chip-selectable chip-unselected';
	}

	onMount(async () => {
		try {
			const [perms, grps] = await Promise.all([
				listPermissions().catch(() => []),
				listGroups().catch(() => [])
			]);
			availablePermissions = perms || [];
			availableGroups = grps || [];

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

	function revertChange(event) {
		const item = event.detail;
		if (!item?.key || !item?.target) return;
		if (item.target === 'permission') {
			togglePermission(item.key);
		} else if (item.target === 'group') {
			toggleGroup(item.key);
		}
	}

	async function handleSubmit() {
		if (!hasChanges) {
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
			const parts = [];
			if (permissionsAdd.length) parts.push(`+${permissionsAdd.length} perm`);
			if (permissionsRemove.length) parts.push(`−${permissionsRemove.length} perm`);
			if (groupsAdd.length) parts.push(`+${groupsAdd.length} group`);
			if (groupsRemove.length) parts.push(`−${groupsRemove.length} group`);
			showToastMessage(`Request submitted (${parts.join(', ')})`, 'success');
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
				<p class="section-subtitle">Request permission or group changes from an admin</p>
			</div>
			<a href="/dashboard" class="w-full sm:w-auto sm:ml-auto">
				<button class="btn-secondary w-full sm:w-auto"><ArrowLeft size={18} />Back to Dashboard</button>
			</a>
		</div>

		<div class="card-muted space-y-4">
			<p class="text-xs text-muted">
				Tap chips to change what you request. Newly selected items are marked with +; items you turn off are
				marked with − and struck through. Submit activates only when something has changed. Click a summary
				item to undo it.
			</p>

			{#if (availablePermissions || []).length === 0}
				<p class="text-muted text-sm">No permissions available.</p>
			{:else}
				<div class="edit-section">
					<h3>Permissions</h3>
					<div class="mb-3">
						<input
							type="text"
							class="input"
							placeholder="Search permissions..."
							bind:value={permissionSearch}
						/>
					</div>
					<div class="chip-selection">
						{#each availablePermissions.filter(
							(p) =>
								!permissionSearch ||
								p.name.toLowerCase().includes(permissionSearch.toLowerCase()) ||
								p.key.toLowerCase().includes(permissionSearch.toLowerCase()) ||
								(p.description &&
									p.description.toLowerCase().includes(permissionSearch.toLowerCase()))
						) as perm (perm.key)}
							<button
								type="button"
								class={chipClass(selectedPermissions.has(perm.key), initialPermissions.has(perm.key))}
								on:click={() => togglePermission(perm.key)}
								title={perm.description}
							>
								{#if selectedPermissions.has(perm.key) && !initialPermissions.has(perm.key)}
									<span class="chip-check">+</span>
								{:else if !selectedPermissions.has(perm.key) && initialPermissions.has(perm.key)}
									<span class="chip-check">−</span>
								{:else if selectedPermissions.has(perm.key)}
									<span class="chip-check">✓</span>
								{/if}
								{perm.name}
							</button>
						{/each}
					</div>
				</div>
			{/if}

			{#if (availableGroups || []).length === 0}
				<p class="text-muted text-sm">No groups available.</p>
			{:else}
				<div class="edit-section">
					<h3>Groups</h3>
					<div class="mb-3">
						<input
							type="text"
							class="input"
							placeholder="Search groups..."
							bind:value={groupSearch}
						/>
					</div>
					<div class="chip-selection">
						{#each availableGroups.filter(
							(g) =>
								!groupSearch ||
								g.name.toLowerCase().includes(groupSearch.toLowerCase()) ||
								g.key.toLowerCase().includes(groupSearch.toLowerCase()) ||
								(g.description &&
									g.description.toLowerCase().includes(groupSearch.toLowerCase()))
						) as group (group.key)}
							<button
								type="button"
								class={groupChipClass(selectedGroups.has(group.key), initialGroups.has(group.key))}
								on:click={() => toggleGroup(group.key)}
								title={group.description}
							>
								{#if selectedGroups.has(group.key) && !initialGroups.has(group.key)}
									<span class="chip-check">+</span>
								{:else if !selectedGroups.has(group.key) && initialGroups.has(group.key)}
									<span class="chip-check">−</span>
								{:else if selectedGroups.has(group.key)}
									<span class="chip-check">✓</span>
								{/if}
								{group.name}
							</button>
						{/each}
					</div>
				</div>
			{/if}

			<ChangeSummary
				title="Request summary"
				items={changeItems}
				emptyText="Toggle chips above to build a request."
				on:revert={revertChange}
			/>

			<div class="flex justify-center sm:justify-start">
				<button
					class="btn-secondary w-full sm:w-auto min-w-[9rem]"
					type="button"
					on:click={handleSubmit}
					disabled={loading || !hasChanges}
				>
					<Send size={18} />
					{loading ? 'Submitting...' : hasChanges ? 'Submit Request' : 'No changes'}
				</button>
			</div>
		</div>
	</div>
</div>

{#if showToast}
	<div class="toast" class:toast-success={toastType === 'success'} class:toast-error={toastType === 'error'}>
		{toastMessage}
	</div>
{/if}

<style>
	.edit-section {
		margin: 0;
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
