<script>
	import { createEventDispatcher } from 'svelte';

	/** @type {{ label: string, kind: 'add' | 'remove' | 'change', target?: string, key?: string }[]} */
	export let items = [];
	export let title = 'Changes';
	export let emptyText = '';

	const dispatch = createEventDispatcher();

	$: added = items.filter((i) => i.kind === 'add');
	$: removed = items.filter((i) => i.kind === 'remove');
	$: changed = items.filter((i) => i.kind === 'change');

	function handleRevert(item) {
		dispatch('revert', item);
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
							on:click={() => handleRevert(item)}
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
							on:click={() => handleRevert(item)}
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
							on:click={() => handleRevert(item)}
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
