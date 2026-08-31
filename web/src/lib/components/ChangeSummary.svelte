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
	<div class="change-summary">
		<p class="change-summary-title">{title}</p>

		{#if added.length > 0}
			<div class="change-summary-section">
				<p class="change-summary-section-label">Added</p>
				<div class="change-summary-items">
					{#each added as item}
						<button
							type="button"
							class="change-summary-item chip-pending"
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
			<div class="change-summary-section">
				<p class="change-summary-section-label">Removed</p>
				<div class="change-summary-items">
					{#each removed as item}
						<button
							type="button"
							class="change-summary-item chip-pending"
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
			<div class="change-summary-section">
				<p class="change-summary-section-label">Changed</p>
				<div class="change-summary-items">
					{#each changed as item}
						<button
							type="button"
							class="change-summary-item chip-pending"
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
	<p class="text-sm text-muted">{emptyText}</p>
{/if}
