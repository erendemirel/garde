<script>
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { listUsers } from '$lib/api';
	import { CircleCheck, CircleX, CircleAlert } from 'lucide-svelte';

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
	let itemsPerPage = 10;
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

	$: totalPages = Math.max(1, Math.ceil(totalCount / itemsPerPage));
	$: startIndex = totalCount === 0 ? 0 : (currentPage - 1) * itemsPerPage;
	$: endIndex = Math.min(startIndex + users.length, totalCount);

	$: pageNumbers = (() => {
		const pages = new Set([1, totalPages]);
		for (let i = currentPage - 1; i <= currentPage + 1; i++) {
			if (i >= 1 && i <= totalPages) pages.add(i);
		}
		return [...pages].sort((a, b) => a - b);
	})();

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

	function getStatusClass(/** @type {string} */ status) {
		const s = status.toLowerCase();
		if (s === 'ok') return 'ok';
		if (s.includes('locked') || s.includes('disabled') || s.includes('rejected')) return 'locked';
		if (s.includes('pending')) return 'pending';
		return 'pending';
	}

	function formatStatus(/** @type {string} */ status) {
		const s = (status || '').toLowerCase();
		if (s === 'ok') return 'OK';
		if (s === 'pending admin approval') return 'Pending approval by an admin';
		if (s === 'admin approval rejected') return 'Approval rejected by an admin';
		if (s === 'locked by admin') return 'Locked by an admin';
		if (s === 'locked by security') return 'Locked by security';
		return status;
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

	function goToPage(/** @type {number} */ page) {
		currentPage = page;
	}

	function previousPage() {
		if (currentPage > 1) currentPage -= 1;
	}

	function nextPage() {
		if (currentPage < totalPages) currentPage += 1;
	}
</script>

{#if loading}
	<p class="text-muted">Loading users...</p>
{:else if error}
	<p class="error">{error}</p>
{:else}
	<div class="space-y-4">
		<div class="flex items-end gap-3 flex-wrap">
			<label class="form-label flex-1 max-w-md">
				<span>Search by email</span>
				<input
					class="input"
					type="search"
					placeholder="Enter email to search..."
					bind:value={searchInput}
					on:input={onSearchInput}
				/>
			</label>
			<label class="form-label">
				<span>Per page</span>
				<select
					class="input w-auto"
					bind:value={itemsPerPage}
					on:change={() => {
						itemsPerPage = Number(itemsPerPage);
						currentPage = 1;
					}}
				>
					<option value={10}>10</option>
					<option value={25}>25</option>
					<option value={50}>50</option>
					<option value={100}>100</option>
				</select>
			</label>
			{#if totalCount > 0}
				<div class="flex items-center gap-2 text-sm text-muted pb-2">
					<span>Showing {startIndex + 1}-{endIndex} of {totalCount}</span>
				</div>
			{/if}
		</div>

		<table class="table-base">
			<thead>
				<tr>
					<th aria-sort={sortAria('email')}>
						<button
							type="button"
							class="flex items-center gap-1 hover:text-accent transition-colors"
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
			<tbody>
				{#if users.length === 0}
					<tr>
						<td colspan="5" class="text-center text-muted py-4">
							{searchQuery ? 'No users found matching your search.' : 'No users found.'}
						</td>
					</tr>
				{:else}
					{#each users as u}
						<tr>
							<td>{u.email}</td>
							<td>
								<span class="status-display status-{getStatusClass(u.status)}">
									<span class="status-icon">
										{#if getStatusClass(u.status) === 'ok'}
											<CircleCheck size={18} />
										{:else if getStatusClass(u.status) === 'locked'}
											<CircleX size={18} />
										{:else}
											<CircleAlert size={18} />
										{/if}
									</span>
									<span class="status-text">{formatStatus(u.status)}</span>
								</span>
							</td>
							<td>
								{#if u.mfa_enabled && u.mfa_enforced}
									<span class="text-blue-600">Enforced and set up</span>
								{:else if u.mfa_enabled}
									<span class="text-green-700">Set up although not enforced</span>
								{:else if u.mfa_enforced}
									<span class="text-red-600">Enforced but not set up</span>
								{:else}
									<span class="text-orange-500">Not enforced and not set up</span>
								{/if}
							</td>
							<td>
								{#if u.pending_updates}
									<span class="badge badge-pending">Update requested</span>
								{:else}
									—
								{/if}
							</td>
							<td>
								<a href="{detailBase}/{u.id}" class="btn-small">View</a>
							</td>
						</tr>
					{/each}
				{/if}
			</tbody>
		</table>

		{#if totalPages > 1 && totalCount > 0}
			<div class="flex items-center justify-center gap-2 mt-4">
				<button
					type="button"
					class="btn-secondary px-3 py-1 text-sm"
					on:click={previousPage}
					disabled={currentPage === 1}
				>
					Previous
				</button>

				{#each pageNumbers as page, i}
					{#if i > 0 && page - pageNumbers[i - 1] > 1}
						<span class="text-muted">...</span>
					{/if}
					<button
						type="button"
						class="btn-secondary px-3 py-1 text-sm {currentPage === page
							? 'bg-accent/20 border-accent'
							: ''}"
						on:click={() => goToPage(page)}
						aria-current={currentPage === page ? 'page' : undefined}
					>
						{page}
					</button>
				{/each}

				<button
					type="button"
					class="btn-secondary px-3 py-1 text-sm"
					on:click={nextPage}
					disabled={currentPage === totalPages}
				>
					Next
				</button>
			</div>
		{/if}
	</div>
{/if}
