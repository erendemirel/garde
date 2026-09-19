<script>
	/** @type {{
	 *   items?: { label: string, kind: string, target?: string, key?: string }[],
	 *   title?: string,
	 *   emptyText?: string,
	 *   onRevert?: (item: { label: string, kind: string, target?: string, key?: string }) => void
	 * }} */
	let {
		items = [],
		title = 'Changes',
		emptyText = '',
		onRevert
	} = $props();

	let added = $derived(items.filter((i) => i.kind === 'add'));
	let removed = $derived(items.filter((i) => i.kind === 'remove'));
	let changed = $derived(items.filter((i) => i.kind === 'change'));

	/** @param {{ label: string, kind: string, target?: string, key?: string }} item */
	function handleRevert(item) {
		onRevert?.(item);
	}
</script>

{#if items.length > 0}
	<div class="change-summary" data-testid="change-summary">
		<p class="change-summary-title">{title}</p>

		{#if added.length > 0}
			<div class="change-summary-section" data-testid="change-summary-added">
				<p class="change-summary-section-label">Added</p>
				<div class="change-summary-items">
					{#each added as item}
						<button
							type="button"
							class="change-summary-item chip-pending"
							data-testid="change-summary-item"
							data-kind="add"
							data-key={item.key}
							title="Undo"
							onclick={() => handleRevert(item)}
						>
							+ {item.label}
						</button>
					{/each}
				</div>
			</div>
		{/if}

		{#if removed.length > 0}
			<div class="change-summary-section" data-testid="change-summary-removed">
				<p class="change-summary-section-label">Removed</p>
				<div class="change-summary-items">
					{#each removed as item}
						<button
							type="button"
							class="change-summary-item chip-pending"
							data-testid="change-summary-item"
							data-kind="remove"
							data-key={item.key}
							title="Undo"
							onclick={() => handleRevert(item)}
						>
							− {item.label}
						</button>
					{/each}
				</div>
			</div>
		{/if}

		{#if changed.length > 0}
			<div class="change-summary-section" data-testid="change-summary-changed">
				<p class="change-summary-section-label">Changed</p>
				<div class="change-summary-items">
					{#each changed as item}
						<button
							type="button"
							class="change-summary-item chip-pending"
							data-testid="change-summary-item"
							data-kind="change"
							data-key={item.key}
							title="Undo"
							onclick={() => handleRevert(item)}
						>
							~ {item.label}
						</button>
					{/each}
				</div>
			</div>
		{/if}
	</div>
{:else if emptyText}
	<p class="text-sm text-muted" data-testid="change-summary-empty">{emptyText}</p>
{/if}
