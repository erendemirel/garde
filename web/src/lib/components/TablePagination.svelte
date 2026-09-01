<script>
	/** Current 1-based page (bindable) */
	export let page = 1;
	/** Items per page (bindable) */
	export let pageSize = 30;
	/** Total item count across all pages */
	export let total = 0;
	/** Optional prefix for data-testid hooks (e.g. "users-list" → users-list-pagination). */
	export let testIdPrefix = 'table';
	/** @type {number[]} */
	export let pageSizeOptions = [10, 30, 50, 100];


	$: pageSizeNum = Number(pageSize) || 30;
	$: totalPages = Math.max(1, Math.ceil(total / pageSizeNum) || 1);
	$: if (page > totalPages) page = totalPages;
	$: if (page < 1) page = 1;

	$: startIndex = total === 0 ? 0 : (page - 1) * pageSizeNum;
	$: endIndex = Math.min(startIndex + pageSizeNum, total);

	$: pageNumbers = (() => {
		const pages = new Set([1, totalPages]);
		for (let i = page - 1; i <= page + 1; i++) {
			if (i >= 1 && i <= totalPages) pages.add(i);
		}
		return [...pages].sort((a, b) => a - b);
	})();

	function goToPage(/** @type {number} */ p) {
		page = p;
	}

	function previousPage() {
		if (page > 1) page -= 1;
	}

	function nextPage() {
		if (page < totalPages) page += 1;
	}

	function onPageSizeChange() {
		pageSize = Number(pageSize);
		page = 1;
	}
</script>

{#if total > 0}
	<div
		class="flex flex-wrap items-center justify-between gap-3 mt-4"
		data-testid="{testIdPrefix}-pagination"
	>
		<div class="flex items-center gap-2 flex-wrap min-w-0">
			{#if totalPages > 1}
				<button
					type="button"
					class="btn-secondary px-3 py-1 text-sm"
					data-testid="{testIdPrefix}-pagination-prev"
					on:click={previousPage}
					disabled={page === 1}
				>
					Previous
				</button>

				{#each pageNumbers as p, i}
					{#if i > 0 && p - pageNumbers[i - 1] > 1}
						<span class="text-muted">...</span>
					{/if}
					<button
						type="button"
						class="btn-secondary px-3 py-1 text-sm {page === p ? 'bg-accent/20 border-accent' : ''}"
						data-testid="{testIdPrefix}-pagination-page"
						data-page={p}
						on:click={() => goToPage(p)}
						aria-current={page === p ? 'page' : undefined}
					>
						{p}
					</button>
				{/each}

				<button
					type="button"
					class="btn-secondary px-3 py-1 text-sm"
					data-testid="{testIdPrefix}-pagination-next"
					on:click={nextPage}
					disabled={page === totalPages}
				>
					Next
				</button>
			{/if}
			<span class="text-sm text-muted whitespace-nowrap" data-testid="{testIdPrefix}-pagination-summary">
				Showing {startIndex + 1}-{endIndex} of {total}
			</span>
		</div>

		<label class="flex items-center gap-2 text-sm text-muted ml-auto">
			<span class="whitespace-nowrap">Per page</span>
			<select
				class="input w-auto py-1 text-sm"
				data-testid="{testIdPrefix}-pagination-per-page"
				bind:value={pageSize}
				on:change={onPageSizeChange}
			>
				{#each pageSizeOptions as n}
					<option value={n}>{n}</option>
				{/each}
			</select>
		</label>
	</div>
{/if}
