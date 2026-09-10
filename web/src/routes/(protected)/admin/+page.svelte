<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { get } from 'svelte/store';
	import { isAdmin, isSuperuser } from '$lib/stores';
	import { onTabListKeydown } from '$lib/tabs';
	import { Users, Ungroup, Blocks } from 'lucide-svelte';
	import AdminMembershipCatalog from '$lib/components/AdminMembershipCatalog.svelte';
	import UsersListPanel from '$lib/components/UsersListPanel.svelte';

	const TAB_IDS = ['users', 'permissions', 'groups'];

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

	function setActiveTab(/** @type {string} */ tab) {
		activeTab = /** @type {'users' | 'permissions' | 'groups'} */ (tab);
	}
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

			<div
				class="flex gap-1 border-b border-borderc"
				data-testid="admin-tabs"
				role="tablist"
				tabindex="-1"
				aria-label="Admin sections"
				on:keydown={(e) => onTabListKeydown(e, TAB_IDS, activeTab, setActiveTab)}
			>
				<button
					type="button"
					role="tab"
					id="tab-users"
					aria-controls="panel-users"
					tabindex={activeTab === 'users' ? 0 : -1}
					data-testid="admin-tab-users"
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
					id="tab-permissions"
					aria-controls="panel-permissions"
					tabindex={activeTab === 'permissions' ? 0 : -1}
					data-testid="admin-tab-permissions"
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
					id="tab-groups"
					aria-controls="panel-groups"
					tabindex={activeTab === 'groups' ? 0 : -1}
					data-testid="admin-tab-groups"
					aria-selected={activeTab === 'groups'}
					class="px-4 py-2 font-medium transition-colors {activeTab === 'groups'
						? 'text-accent border-b-2 border-accent'
						: 'text-muted hover:text-accent'}"
					on:click={() => setActiveTab('groups')}
				>
					<Blocks size={18} class="inline mr-2" />
					Groups
				</button>
			</div>

			{#if activeTab === 'users'}
				<div
					role="tabpanel"
					id="panel-users"
					aria-labelledby="tab-users"
					data-testid="admin-panel-users"
				>
					<UsersListPanel detailBase="/admin/users" />
				</div>
			{:else if activeTab === 'permissions'}
				<div
					role="tabpanel"
					id="panel-permissions"
					aria-labelledby="tab-permissions"
					data-testid="admin-panel-permissions"
				>
					<AdminMembershipCatalog mode="permissions" />
				</div>
			{:else}
				<div
					role="tabpanel"
					id="panel-groups"
					aria-labelledby="tab-groups"
					data-testid="admin-panel-groups"
				>
					<AdminMembershipCatalog mode="groups" />
				</div>
			{/if}
		{/if}
	</div>
</div>
