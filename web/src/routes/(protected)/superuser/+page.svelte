<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { get } from 'svelte/store';
	import { isSuperuser } from '$lib/stores';
	import { Users, Ungroup, Blocks, Combine, ShieldUser } from 'lucide-svelte';
	import UsersListPanel from '$lib/components/UsersListPanel.svelte';
	import SuperuserCatalogPanel from '$lib/components/SuperuserCatalogPanel.svelte';
	import SuperuserVisibilityPanel from '$lib/components/SuperuserVisibilityPanel.svelte';
	import SuperuserAdminManagementPanel from '$lib/components/SuperuserAdminManagementPanel.svelte';

	const SUPERUSER_TABS = new Set([
		'users',
		'permissions',
		'groups',
		'visibility',
		'admin-management'
	]);

	let activeTab = 'users';
	let accessDenied = false;
	let checking = true;

	onMount(() => {
		const tab = get(page).url.searchParams.get('tab');
		if (tab && SUPERUSER_TABS.has(tab)) {
			activeTab = tab;
		}
		if (!get(isSuperuser)) {
			accessDenied = true;
		}
		checking = false;
	});

	function setActiveTab(/** @type {string} */ tab) {
		activeTab = tab;
		goto(`/superuser?tab=${tab}`, { replaceState: true, keepFocus: true, noScroll: true });
	}
</script>

<svelte:head>
	<title>Superuser | garde</title>
</svelte:head>

<div class="container-wide" data-testid="superuser-page">
	<div class="card space-y-4">
		{#if checking}
			<p class="text-muted" data-testid="superuser-loading">Loading...</p>
		{:else if accessDenied}
			<h1 class="text-xl font-bold text-error" data-testid="superuser-access-denied">Access Denied</h1>
			<p class="text-muted mb-4">
				You don't have permission to access this page. Superuser privileges are required.
			</p>
			<a href="/dashboard" class="btn-secondary" data-testid="superuser-back-dashboard">Back to Dashboard</a>
		{:else}
			<div>
				<h1 class="page-title">Superuser</h1>
				<p class="section-subtitle">
					Manage all users, permissions, groups, visibility, and admin scope
				</p>
			</div>

			<div class="flex gap-2 border-b border-borderc flex-wrap" data-testid="superuser-tabs" role="tablist">
				<button
					type="button"
					role="tab"
					data-testid="superuser-tab-users"
					aria-selected={activeTab === 'users'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'users'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => setActiveTab('users')}
				>
					<Users size={18} class="inline mr-2" />
					Users
				</button>
				<button
					type="button"
					role="tab"
					data-testid="superuser-tab-permissions"
					aria-selected={activeTab === 'permissions'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'permissions'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => setActiveTab('permissions')}
				>
					<Ungroup size={18} class="inline mr-2" />
					Permissions
				</button>
				<button
					type="button"
					role="tab"
					data-testid="superuser-tab-groups"
					aria-selected={activeTab === 'groups'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'groups'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => setActiveTab('groups')}
				>
					<Blocks size={18} class="inline mr-2" />
					Groups
				</button>
				<button
					type="button"
					role="tab"
					data-testid="superuser-tab-visibility"
					aria-selected={activeTab === 'visibility'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'visibility'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => setActiveTab('visibility')}
				>
					<Combine size={18} class="inline mr-2" />
					Permission Visibility
				</button>
				<button
					type="button"
					role="tab"
					data-testid="superuser-tab-admin-management"
					aria-selected={activeTab === 'admin-management'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'admin-management'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => setActiveTab('admin-management')}
				>
					<ShieldUser size={18} class="inline mr-2" />
					Admin-User Management
				</button>
			</div>

			{#if activeTab === 'users'}
				<div class="space-y-4" data-testid="superuser-users-panel">
					<div>
						<h2 class="section-title">Users</h2>
						<p class="text-sm text-muted mt-1">
							All accounts in the system. Superuser can change status, access, and membership for any
							user.
						</p>
					</div>
					<UsersListPanel detailBase="/admin/users" />
				</div>
			{:else if activeTab === 'permissions'}
				<SuperuserCatalogPanel mode="permissions" />
			{:else if activeTab === 'groups'}
				<SuperuserCatalogPanel mode="groups" />
			{:else if activeTab === 'visibility'}
				<SuperuserVisibilityPanel />
			{:else if activeTab === 'admin-management'}
				<SuperuserAdminManagementPanel />
			{/if}
		{/if}
	</div>
</div>
