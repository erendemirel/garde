<script>
	/** @type {{
	 *   page?: number,
	 *   pageSize?: number,
	 *   total?: number,
	 *   testIdPrefix?: string,
	 *   pageSizeOptions?: number[]
	 * }} */
	let {
		page = $bindable(1),
		pageSize = $bindable(30),
		total = 0,
		testIdPrefix = 'table',
		pageSizeOptions = [10, 30, 50, 100]
	} = $props();

	let pageSizeNum = $derived(Number(pageSize) || 30);
	let totalPages = $derived(Math.max(1, Math.ceil(total / pageSizeNum) || 1));

	$effect(() => {
		if (page > totalPages) page = totalPages;
		else if (page < 1) page = 1;
	});

	let startIndex = $derived(total === 0 ? 0 : (page - 1) * pageSizeNum);
	let endIndex = $derived(Math.min(startIndex + pageSizeNum, total));

	let pageNumbers = $derived.by(() => {
		const pages = new Set([1, totalPages]);
		for (let i = page - 1; i <= page + 1; i++) {
			if (i >= 1 && i <= totalPages) pages.add(i);
		}
		return [...pages].sort((a, b) => a - b);
	});

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
					onclick={previousPage}
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
						onclick={() => goToPage(p)}
						aria-current={page === p ? 'page' : undefined}
					>
						{p}
					</button>
				{/each}

				<button
					type="button"
					class="btn-secondary px-3 py-1 text-sm"
					data-testid="{testIdPrefix}-pagination-next"
					onclick={nextPage}
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
				onchange={onPageSizeChange}
			>
				{#each pageSizeOptions as n}
					<option value={n}>{n}</option>
				{/each}
			</select>
		</label>
	</div>
{/if}
