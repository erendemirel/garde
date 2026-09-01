<script>
	import { onMount } from 'svelte';
	import { requestUpdate, listPermissions, listGroups } from '$lib/api';
	import { showToast } from '$lib/toast';
	import { goto } from '$app/navigation';
	import { user } from '$lib/stores';
	import { refreshSession } from '$lib/session';
	import { ArrowLeft, Send } from 'lucide-svelte';
	import ChangeSummary from '$lib/components/ChangeSummary.svelte';
	import MultiSelectChips from '$lib/components/MultiSelectChips.svelte';

	let loading = false;
	let catalogLoading = true;
	let formReady = false;

	let availablePermissions = [];
	let availableGroups = [];
	let selectedPermissions = new Set();
	let selectedGroups = new Set();
	let initialPermissions = new Set();
	let initialGroups = new Set();

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
	$: catalogReady = formReady && !catalogLoading;

	onMount(async () => {
		formReady = true;
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
		} finally {
			catalogLoading = false;
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
		if (!catalogReady || loading || !hasChanges) return;

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
			showToast(`Request submitted (${parts.join(', ')})`, 'success');
			await refreshSession();
			await goto('/dashboard');
		} catch (e) {
			showToast(e instanceof Error ? e.message : 'Request failed', 'error');
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>Request Update | garde</title>
</svelte:head>

<div class="container-medium" data-testid="request-update-page">
	<div class="card space-y-4">
		<div class="flex items-start justify-between gap-3">
			<div>
				<h1 class="page-title">Request Update</h1>
				<p class="section-subtitle">Request permission or group changes from an admin</p>
			</div>
			<a
				href="/dashboard"
				class="btn-secondary w-full sm:w-auto sm:ml-auto"
				data-testid="request-update-back"
				><ArrowLeft size={18} />Back to Dashboard</a
			>
		</div>

		<div
			class="card-muted space-y-4"
			data-testid="request-update-form"
			data-ready={catalogReady ? 'true' : 'false'}
			aria-busy={!catalogReady}
		>
			<p class="text-xs text-muted">
				Ask an admin to change your permissions or groups. You can only request permissions visible to your
				groups. Changes take effect after an admin who shares a group with you approves the request.
			</p>

			{#if catalogLoading}
				<p class="text-muted text-sm" data-testid="request-update-catalog-loading">Loading options…</p>
			{:else if (availablePermissions || []).length === 0}
				<p class="text-muted text-sm" data-testid="request-update-permissions-empty">No permissions available.</p>
			{:else}
				<div class="edit-section" data-testid="request-update-permissions">
					<h3>Permissions</h3>
					<MultiSelectChips
						options={availablePermissions}
						bind:selected={selectedPermissions}
						initial={initialPermissions}
						variant="permission"
						placeholder="Search permissions to add…"
						label="Permissions"
					/>
				</div>
			{/if}

			{#if catalogLoading}
				<!-- loading message shown above -->
			{:else if (availableGroups || []).length === 0}
				<p class="text-muted text-sm" data-testid="request-update-groups-empty">No groups available.</p>
			{:else}
				<div class="edit-section" data-testid="request-update-groups">
					<h3>Groups</h3>
					<MultiSelectChips
						options={availableGroups}
						bind:selected={selectedGroups}
						initial={initialGroups}
						variant="group"
						placeholder="Search groups to add…"
						label="Groups"
					/>
				</div>
			{/if}

			<ChangeSummary
				title="Request summary"
				items={changeItems}
				emptyText="No permission or group changes selected yet."
				on:revert={revertChange}
			/>

			<div class="flex justify-center sm:justify-start">
				<button
					class="btn-secondary w-full sm:w-auto min-w-[9rem]"
					type="button"
					data-testid="request-update-submit"
					on:click={handleSubmit}
					disabled={!catalogReady || loading || !hasChanges}
				>
					<Send size={18} />
					{loading ? 'Submitting...' : !catalogReady ? 'Loading...' : hasChanges ? 'Submit Request' : 'No changes'}
				</button>
			</div>
		</div>
	</div>
</div>

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
