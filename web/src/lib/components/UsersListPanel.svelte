<script>
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { listUsers } from '$lib/api';
	import { Edit } from 'lucide-svelte';
	import TablePagination from '$lib/components/TablePagination.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import MfaLabel from '$lib/components/MfaLabel.svelte';

	/** Base path for user detail links, e.g. "/admin/users" */
	export let detailBase = '/admin/users';

	/** @type {import('$lib/api').User[]} */
	let users = [];
	let error = '';
	let loading = true;
	let searchInput = '';
	let searchQuery = '';
	let sortField = 'email';
	let sortDirection = 'asc';
	let currentPage = 1;
	let itemsPerPage = 30;
	let totalCount = 0;
	let ready = false;
	/** @type {ReturnType<typeof setTimeout> | undefined} */
	let searchTimer;
	let fetchGen = 0;

	onMount(() => {
		ready = true;
		return () => {
			if (searchTimer) clearTimeout(searchTimer);
		};
	});

	$: if (browser && ready) {
		searchQuery;
		sortField;
		sortDirection;
		currentPage;
		itemsPerPage;
		void fetchUsers();
	}

	async function fetchUsers() {
		const gen = ++fetchGen;
		try {
			const res = await listUsers({
				q: searchQuery,
				sort: sortField,
				order: sortDirection,
				page: currentPage,
				limit: Number(itemsPerPage)
			});
			if (gen !== fetchGen) return;
			users = res.users || [];
			totalCount = res.total ?? users.length;
			error = '';
		} catch (e) {
			if (gen !== fetchGen) return;
			error = e instanceof Error ? e.message : 'Failed to load users';
		}
		if (gen === fetchGen) loading = false;
	}

	/** @param {'email' | 'status' | 'mfa' | 'pending'} field */
	function handleSort(field) {
		if (sortField === field) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			sortField = field;
			sortDirection = 'asc';
		}
		currentPage = 1;
	}

	/** @param {'email' | 'status' | 'mfa' | 'pending'} field */
	function sortAria(field) {
		if (sortField !== field) return 'none';
		return sortDirection === 'asc' ? 'ascending' : 'descending';
	}

	function onSearchInput() {
		if (searchTimer) clearTimeout(searchTimer);
		searchTimer = setTimeout(() => {
			searchQuery = searchInput.trim();
			currentPage = 1;
		}, 300);
	}
</script>

{#if loading}
	<p class="text-muted" data-testid="users-list-loading">Loading users...</p>
{:else if error}
	<p class="error" data-testid="users-list-error">{error}</p>
{:else}
	<div class="space-y-4" data-testid="users-list">
		<label class="form-label max-w-md">
			<span>Search by email</span>
			<input
				class="input"
				type="search"
				data-testid="users-list-search"
				placeholder="Enter email to search..."
				bind:value={searchInput}
				on:input={onSearchInput}
			/>
		</label>

		<!-- Desktop / wide table -->
		<div class="table-scroll hidden sm:block" data-testid="users-list-table-wrap">
			<table class="table-base" data-testid="users-list-table">
				<thead>
					<tr>
						<th aria-sort={sortAria('email')}>
							<button
								type="button"
								class="flex items-center gap-1 hover:text-accent transition-colors"
								data-testid="users-list-sort-email"
								on:click={() => handleSort('email')}
							>
								Email
								{#if sortField === 'email'}
									<span class="text-xs" aria-hidden="true">{sortDirection === 'asc' ? '↑' : '↓'}</span>
								{/if}
							</button>
						</th>
						<th aria-sort={sortAria('status')}>
							<button
								type="button"
								class="flex items-center gap-1 hover:text-accent transition-colors"
								data-testid="users-list-sort-status"
								on:click={() => handleSort('status')}
							>
								Status
								{#if sortField === 'status'}
									<span class="text-xs" aria-hidden="true">{sortDirection === 'asc' ? '↑' : '↓'}</span>
								{/if}
							</button>
						</th>
						<th aria-sort={sortAria('mfa')}>
							<button
								type="button"
								class="flex items-center gap-1 hover:text-accent transition-colors"
								data-testid="users-list-sort-mfa"
								on:click={() => handleSort('mfa')}
							>
								MFA
								{#if sortField === 'mfa'}
									<span class="text-xs" aria-hidden="true">{sortDirection === 'asc' ? '↑' : '↓'}</span>
								{/if}
							</button>
						</th>
						<th aria-sort={sortAria('pending')}>
							<button
								type="button"
								class="flex items-center gap-1 hover:text-accent transition-colors"
								data-testid="users-list-sort-pending"
								on:click={() => handleSort('pending')}
							>
								Pending
								{#if sortField === 'pending'}
									<span class="text-xs" aria-hidden="true">{sortDirection === 'asc' ? '↑' : '↓'}</span>
								{/if}
							</button>
						</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody data-testid="users-list-tbody">
					{#if users.length === 0}
						<tr data-testid="users-list-empty">
							<td colspan="5" class="text-center text-muted py-4">
								{searchQuery ? 'No users found matching your search.' : 'No users found.'}
							</td>
						</tr>
					{:else}
						{#each users as u}
							<tr data-testid="users-list-row" data-user-id={u.id} data-user-email={u.email}>
								<td data-testid="users-list-row-email">{u.email}</td>
								<td><StatusBadge status={u.status} /></td>
								<td>
									<MfaLabel enabled={u.mfa_enabled} enforced={u.mfa_enforced} compact />
								</td>
								<td>
									{#if u.pending_updates}
										<span class="badge badge-pending">Update requested</span>
									{:else}
										—
									{/if}
								</td>
								<td>
									<a
										href="{detailBase}/{u.id}"
										class="btn-icon"
										title="Edit user"
										aria-label="Edit user {u.email}"
										data-testid="users-list-edit"
										data-user-id={u.id}
									>
										<Edit size={20} />
									</a>
								</td>
							</tr>
						{/each}
					{/if}
				</tbody>
			</table>
		</div>

		<!-- Narrow viewport cards -->
		<div class="space-y-3 sm:hidden" data-testid="users-list-cards">
			{#if users.length === 0}
				<p class="text-center text-muted py-4" data-testid="users-list-empty">
					{searchQuery ? 'No users found matching your search.' : 'No users found.'}
				</p>
			{:else}
				{#each users as u}
					<a
						href="{detailBase}/{u.id}"
						class="block rounded-lg border border-borderc bg-input p-3 no-underline text-text hover:border-accent/40"
						data-testid="users-list-card"
						data-user-id={u.id}
						data-user-email={u.email}
					>
						<p class="font-semibold text-sm break-all">{u.email}</p>
						<div class="mt-2 flex flex-wrap items-center gap-2 text-sm">
							<StatusBadge status={u.status} />
							<MfaLabel enabled={u.mfa_enabled} enforced={u.mfa_enforced} compact />
							{#if u.pending_updates}
								<span class="badge badge-pending">Update requested</span>
							{/if}
						</div>
					</a>
				{/each}
			{/if}
		</div>

		<TablePagination bind:page={currentPage} bind:pageSize={itemsPerPage} total={totalCount} />
	</div>
{/if}
