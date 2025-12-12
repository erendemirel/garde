<script>
	import { onMount } from 'svelte';
	import { listUsers } from '$lib/api';
	import { isAdmin } from '$lib/stores';
	import { CircleCheck, CircleX, CircleAlert, ArrowLeft } from 'lucide-svelte';

	let users = [];
	let error = '';
	let accessDenied = false;
	let loading = true;
	let searchQuery = '';
	let sortField = 'email';
	let sortDirection = 'asc';
	let currentPage = 1;
	let itemsPerPage = 10;

	onMount(async () => {
		try {
			const res = await listUsers();
			users = res.users || [];
			isAdmin.set(true);
		} catch (e) {
			const msg = e instanceof Error ? e.message : '';
			if (msg.toLowerCase().includes('unauthorized') || 
				msg.toLowerCase().includes('forbidden') ||
				msg.toLowerCase().includes('permission')) {
				accessDenied = true;
				isAdmin.set(false);
			} else {
				error = msg || 'Failed to load users';
			}
		}
		loading = false;
	});

	function getStatusClass(status) {
		const s = status.toLowerCase();
		if (s === 'ok') return 'ok';
		if (s.includes('locked') || s.includes('disabled')) return 'locked';
		if (s.includes('pending')) return 'pending';
		return 'pending';
	}

	function handleSort(field) {
		if (sortField === field) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			sortField = field;
			sortDirection = 'asc';
		}
	}

	$: filteredAndSortedUsers = (() => {
		let filtered = users;
		
		// Filter by email search
		if (searchQuery.trim()) {
			const query = searchQuery.toLowerCase().trim();
			filtered = users.filter(u => u.email.toLowerCase().includes(query));
		}
		
		// Sort
		const sorted = [...filtered].sort((a, b) => {
			let aVal, bVal;
			
			switch (sortField) {
				case 'email':
					aVal = a.email.toLowerCase();
					bVal = b.email.toLowerCase();
					break;
				case 'status':
					aVal = a.status.toLowerCase();
					bVal = b.status.toLowerCase();
					break;
				case 'mfa':
					aVal = (a.mfa_enabled ? '1' : '0') + (a.mfa_enforced ? '1' : '0');
					bVal = (b.mfa_enabled ? '1' : '0') + (b.mfa_enforced ? '1' : '0');
					break;
				case 'pending':
					aVal = a.pending_updates ? '1' : '0';
					bVal = b.pending_updates ? '1' : '0';
					break;
				default:
					return 0;
			}
			
			if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
			if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
			return 0;
		});
		
		return sorted;
	})();

	$: totalPages = Math.ceil(filteredAndSortedUsers.length / itemsPerPage);
	$: startIndex = (currentPage - 1) * itemsPerPage;
	$: endIndex = startIndex + itemsPerPage;
	$: paginatedUsers = filteredAndSortedUsers.slice(startIndex, endIndex);

	$: if (currentPage > totalPages && totalPages > 0) {
		currentPage = totalPages;
	}

	function goToPage(page) {
		if (page >= 1 && page <= totalPages) {
			currentPage = page;
		}
	}

	function previousPage() {
		if (currentPage > 1) {
			currentPage--;
		}
	}

	function nextPage() {
		if (currentPage < totalPages) {
			currentPage++;
		}
	}
</script>

<svelte:head>
	<title>Admin | garde</title>
</svelte:head>

<div class="container-wide">
	<div class="card space-y-4">
		{#if accessDenied}
			<h1 class="text-xl font-bold text-error">Access Denied</h1>
			<p class="text-muted mb-4">
				You don't have permission to access this page. Admin privileges are required.
			</p>
			<a href="/dashboard"><button class="btn-secondary">Back to Dashboard</button></a>
		{:else}
			<h1 class="page-title">User Management</h1>

		{#if loading}
			<p class="text-muted">Loading users...</p>
		{:else if error}
			<p class="error">{error}</p>
		{:else if users.length === 0}
			<p class="text-muted">No users found.</p>
		{:else}
			<div class="space-y-4">
				<div class="flex items-center gap-3 flex-wrap">
					<label class="form-label flex-1 max-w-md">
						<span>Search by email</span>
						<input 
							class="input" 
							type="text" 
							placeholder="Enter email to search..." 
							bind:value={searchQuery}
							on:input={() => currentPage = 1}
						/>
					</label>
					{#if filteredAndSortedUsers.length > 0}
						<div class="flex items-center gap-2 text-sm text-muted">
							<span>Showing {startIndex + 1}-{Math.min(endIndex, filteredAndSortedUsers.length)} of {filteredAndSortedUsers.length}</span>
						</div>
					{/if}
				</div>

			<table class="table-base">
				<thead>
					<tr>
							<th>
								<button 
									class="flex items-center gap-1 hover:text-accent transition-colors" 
									on:click={() => handleSort('email')}
								>
									Email
									{#if sortField === 'email'}
										<span class="text-xs">{sortDirection === 'asc' ? '↑' : '↓'}</span>
									{/if}
								</button>
							</th>
							<th>
								<button 
									class="flex items-center gap-1 hover:text-accent transition-colors" 
									on:click={() => handleSort('status')}
								>
									Status
									{#if sortField === 'status'}
										<span class="text-xs">{sortDirection === 'asc' ? '↑' : '↓'}</span>
									{/if}
								</button>
							</th>
							<th>
								<button 
									class="flex items-center gap-1 hover:text-accent transition-colors" 
									on:click={() => handleSort('mfa')}
								>
									MFA
									{#if sortField === 'mfa'}
										<span class="text-xs">{sortDirection === 'asc' ? '↑' : '↓'}</span>
									{/if}
								</button>
							</th>
							<th>
								<button 
									class="flex items-center gap-1 hover:text-accent transition-colors" 
									on:click={() => handleSort('pending')}
								>
									Pending
									{#if sortField === 'pending'}
										<span class="text-xs">{sortDirection === 'asc' ? '↑' : '↓'}</span>
									{/if}
								</button>
							</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
						{#if filteredAndSortedUsers.length === 0}
							<tr>
								<td colspan="5" class="text-center text-muted py-4">No users found matching your search.</td>
							</tr>
						{:else}
							{#each paginatedUsers as u}
						<tr class="hover:bg-white/5">
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
									<span class="status-text">{u.status}</span>
								</span>
							</td>
							<td>{u.mfa_enabled ? '' : '—'}{u.mfa_enforced ? ' (enforced)' : ''}</td>
							<td>
								{#if u.pending_updates}
									<span class="badge badge-pending">Update requested</span>
								{:else}
									—
								{/if}
							</td>
							<td>
								<a href="/admin/users/{u.id}">
									<button class="btn-small">
										View
									</button>
								</a>
							</td>
						</tr>
					{/each}
						{/if}
				</tbody>
			</table>

				{#if totalPages > 1}
					<div class="flex items-center justify-center gap-2 mt-4">
						<button 
							class="btn-secondary px-3 py-1 text-sm" 
							on:click={previousPage}
							disabled={currentPage === 1}
						>
							Previous
						</button>
						
						{#each Array(totalPages) as _, i}
							{@const page = i + 1}
							{#if page === 1 || page === totalPages || (page >= currentPage - 1 && page <= currentPage + 1)}
								<button 
									class="btn-secondary px-3 py-1 text-sm {currentPage === page ? 'bg-accent/20 border-accent' : ''}" 
									on:click={() => goToPage(page)}
								>
									{page}
								</button>
							{:else if page === currentPage - 2 || page === currentPage + 2}
								<span class="text-muted">...</span>
							{/if}
						{/each}
						
						<button 
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
		{/if}
	</div>
</div>

