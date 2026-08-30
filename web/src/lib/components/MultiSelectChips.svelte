<script>
	import { createEventDispatcher, onMount } from 'svelte';
	import { X } from 'lucide-svelte';

	/** @type {{ key: string, name: string, description?: string }[]} */
	export let options = [];
	/** @type {Set<string>} */
	export let selected = new Set();
	/** @type {Set<string>} */
	export let initial = new Set();
	/** @type {'permission' | 'group'} */
	export let variant = 'permission';
	export let placeholder = 'Search to add…';
	export let label = '';

	const dispatch = createEventDispatcher();
	const listId = `ms-list-${Math.random().toString(36).slice(2, 9)}`;

	let query = '';
	let open = false;
	let highlight = 0;
	/** @type {HTMLElement | null} */
	let rootEl = null;
	/** @type {HTMLInputElement | null} */
	let inputEl = null;

	$: selectedStyle = variant === 'group' ? 'badge-group' : 'badge-permission';

	/** Selected chips, then pending removals (still visible until undo). */
	$: trayItems = [
		...options.filter((o) => selected.has(o.key)).map((o) => ({ ...o, state: pendingState(o.key) })),
		...options
			.filter((o) => !selected.has(o.key) && initial.has(o.key))
			.map((o) => ({ ...o, state: 'removed' }))
	];

	/** Addable options: not selected; pending removals stay in the tray only. */
	$: filtered = options.filter((o) => {
		if (selected.has(o.key)) return false;
		if (initial.has(o.key) && !selected.has(o.key)) return false;
		if (!query) return true;
		const q = query.toLowerCase();
		return (
			o.name.toLowerCase().includes(q) ||
			o.key.toLowerCase().includes(q) ||
			(o.description && o.description.toLowerCase().includes(q))
		);
	});

	$: if (highlight >= filtered.length) highlight = Math.max(0, filtered.length - 1);

	function pendingState(key) {
		if (selected.has(key) && !initial.has(key)) return 'added';
		if (!selected.has(key) && initial.has(key)) return 'removed';
		return 'selected';
	}

	function chipClass(state) {
		if (state === 'added') return 'ms-chip chip-pending';
		if (state === 'removed') return 'ms-chip chip-pending chip-pending-removed';
		return `ms-chip ${selectedStyle}`;
	}

	function emit(next) {
		selected = next;
		dispatch('change', next);
	}

	function add(key) {
		if (selected.has(key)) return;
		const next = new Set(selected);
		next.add(key);
		emit(next);
		query = '';
		highlight = 0;
		open = true;
		inputEl?.focus();
	}

	function remove(key) {
		if (!selected.has(key)) return;
		const next = new Set(selected);
		next.delete(key);
		emit(next);
		inputEl?.focus();
	}

	function restore(key) {
		add(key);
	}

	function onChipAction(item) {
		if (item.state === 'removed') restore(item.key);
		else remove(item.key);
	}

	function openList() {
		open = true;
	}

	function closeList() {
		open = false;
		highlight = 0;
	}

	function onInput() {
		open = true;
		highlight = 0;
	}

	function onKeydown(e) {
		if (e.key === 'Escape') {
			if (open) {
				e.preventDefault();
				closeList();
			}
			return;
		}
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			open = true;
			if (filtered.length) highlight = (highlight + 1) % filtered.length;
			return;
		}
		if (e.key === 'ArrowUp') {
			e.preventDefault();
			open = true;
			if (filtered.length) highlight = (highlight - 1 + filtered.length) % filtered.length;
			return;
		}
		if (e.key === 'Enter') {
			if (open && filtered[highlight]) {
				e.preventDefault();
				add(filtered[highlight].key);
			}
			return;
		}
		if (e.key === 'Backspace' && !query && trayItems.length) {
			const lastSelected = [...trayItems].reverse().find((i) => i.state !== 'removed');
			if (lastSelected) {
				e.preventDefault();
				remove(lastSelected.key);
			}
		}
	}

	onMount(() => {
		const onDoc = (e) => {
			if (!rootEl?.contains(e.target)) closeList();
		};
		document.addEventListener('pointerdown', onDoc);
		return () => document.removeEventListener('pointerdown', onDoc);
	});
</script>

<div class="ms-root" bind:this={rootEl} data-variant={variant}>
	{#if label}
		<span class="sr-only">{label}</span>
	{/if}
	<div
		class="ms-field"
		class:ms-field-open={open}
		role="combobox"
		aria-expanded={open}
		aria-haspopup="listbox"
		aria-controls={open ? listId : undefined}
	>
		<input
			bind:this={inputEl}
			class="ms-input"
			type="text"
			{placeholder}
			bind:value={query}
			autocomplete="off"
			aria-autocomplete="list"
			aria-label={label || placeholder}
			on:focus={openList}
			on:input={onInput}
			on:keydown={onKeydown}
		/>
		{#if trayItems.length > 0}
			<div class="ms-tray">
				{#each trayItems as item (item.key + item.state)}
					<button
						type="button"
						class={chipClass(item.state)}
						title={item.description || (item.state === 'removed' ? 'Click to restore' : 'Click to remove')}
						on:click={() => onChipAction(item)}
					>
						{#if item.state === 'added'}
							<span class="ms-chip-mark" aria-hidden="true">+</span>
						{:else if item.state === 'removed'}
							<span class="ms-chip-mark" aria-hidden="true">−</span>
						{/if}
						<span>{item.name}</span>
						{#if item.state !== 'removed'}
							<span class="ms-chip-x" aria-hidden="true"><X size={12} strokeWidth={2.5} /></span>
						{/if}
					</button>
				{/each}
			</div>
		{/if}
	</div>

	{#if open}
		<ul class="ms-dropdown" id={listId} role="listbox">
			{#if filtered.length === 0}
				<li class="ms-empty" role="presentation">
					{query ? 'No matches' : 'Nothing left to add'}
				</li>
			{:else}
				{#each filtered as opt, i (opt.key)}
					<li role="option" aria-selected={i === highlight}>
						<button
							type="button"
							class="ms-option"
							class:ms-option-active={i === highlight}
							title={opt.description}
							on:click={() => add(opt.key)}
							on:mouseenter={() => (highlight = i)}
						>
							<span class="ms-option-name">{opt.name}</span>
							{#if opt.description}
								<span class="ms-option-desc">{opt.description}</span>
							{/if}
						</button>
					</li>
				{/each}
			{/if}
		</ul>
	{/if}
</div>
