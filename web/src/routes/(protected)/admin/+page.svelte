<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { get } from 'svelte/store';
	import { isAdmin, isSuperuser } from '$lib/stores';
	import { Users, Ungroup, Blocks } from 'lucide-svelte';
	import AdminMembershipCatalog from '$lib/components/AdminMembershipCatalog.svelte';
	import UsersListPanel from '$lib/components/UsersListPanel.svelte';

	/** @type {'users' | 'permissions' | 'groups'} */
	let activeTab = 'users';
	let accessDenied = false;
	let checking = true;

	onMount(() => {
		if (get(isSuperuser)) {
			goto('/superuser?tab=users');
			return;
		}
		if (!get(isAdmin)) {
			accessDenied = true;
		}
		checking = false;
	});
</script>

<svelte:head>
	<title>Admin | garde</title>
</svelte:head>

<div class="container-wide" data-testid="admin-page">
	<div class="card space-y-4">
		{#if checking}
			<p class="text-muted" data-testid="admin-loading">Loading...</p>
		{:else if accessDenied}
			<h1 class="text-xl font-bold text-error" data-testid="admin-access-denied">Access Denied</h1>
			<p class="text-muted mb-4">
				You don't have permission to access this page. Admin privileges are required.
			</p>
			<a href="/dashboard" class="btn-secondary" data-testid="admin-back-dashboard">Back to Dashboard</a>
		{:else}
			<div>
				<h1 class="page-title">Admin</h1>
				<p class="section-subtitle">
					Users who share a group with you, plus permissions and groups within your visibility and
					membership.
				</p>
			</div>

			<div class="flex gap-1 border-b border-borderc" data-testid="admin-tabs" role="tablist">
				<button
					type="button"
					role="tab"
					data-testid="admin-tab-users"
					aria-selected={activeTab === 'users'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'users'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => (activeTab = 'users')}
				>
					<Users size={18} class="inline mr-2" />
					Users
				</button>
				<button
					type="button"
					role="tab"
					data-testid="admin-tab-permissions"
					aria-selected={activeTab === 'permissions'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'permissions'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => (activeTab = 'permissions')}
				>
					<Ungroup size={18} class="inline mr-2" />
					Permissions
				</button>
				<button
					type="button"
					role="tab"
					data-testid="admin-tab-groups"
					aria-selected={activeTab === 'groups'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'groups'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => (activeTab = 'groups')}
				>
					<Blocks size={18} class="inline mr-2" />
					Groups
				</button>
			</div>

			{#if activeTab === 'users'}
				<UsersListPanel detailBase="/admin/users" />
			{:else if activeTab === 'permissions'}
				<AdminMembershipCatalog mode="permissions" />
			{:else}
				<AdminMembershipCatalog mode="groups" />
			{/if}
		{/if}
	</div>
</div>
