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
	/** When true, parent supplies options via `search` events (paginated API). Local text filter is skipped. */
	export let remote = false;
	export let remoteHint = 'Type at least 2 characters to search…';

	const PAGE_SIZE = 25;
	const dispatch = createEventDispatcher();
	const listId = `ms-list-${Math.random().toString(36).slice(2, 9)}`;

	let query = '';
	let open = false;
	let highlight = 0;
	let visibleLimit = PAGE_SIZE;
	/** @type {HTMLElement | null} */
	let rootEl = null;
	/** @type {HTMLInputElement | null} */
	let inputEl = null;
	/** @type {HTMLUListElement | null} */
	let listEl = null;
	/** @type {ReturnType<typeof setTimeout> | undefined} */
	let searchTimer;

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
		if (remote) return true;
		if (!query) return true;
		const q = query.toLowerCase();
		return (
			o.name.toLowerCase().includes(q) ||
			o.key.toLowerCase().includes(q) ||
			(o.description && o.description.toLowerCase().includes(q))
		);
	});

	$: visibleOptions = filtered.slice(0, visibleLimit);
	$: hasMore = visibleLimit < filtered.length;

	$: if (highlight >= visibleOptions.length) {
		highlight = Math.max(0, visibleOptions.length - 1);
	}

	function pendingState(/** @type {string} */ key) {
		if (selected.has(key) && !initial.has(key)) return 'added';
		if (!selected.has(key) && initial.has(key)) return 'removed';
		return 'selected';
	}

	function chipClass(/** @type {string} */ state) {
		if (state === 'added') return 'ms-chip chip-pending';
		if (state === 'removed') return 'ms-chip chip-pending chip-pending-removed';
		return `ms-chip ${selectedStyle}`;
	}

	function emit(/** @type {Set<string>} */ next) {
		selected = next;
		dispatch('change', next);
	}

	function resetVisible() {
		visibleLimit = PAGE_SIZE;
		highlight = 0;
		if (listEl) listEl.scrollTop = 0;
	}

	function add(/** @type {string} */ key) {
		if (selected.has(key)) return;
		const next = new Set(selected);
		next.add(key);
		emit(next);
		query = '';
		resetVisible();
		open = true;
		inputEl?.focus();
	}

	function remove(/** @type {string} */ key) {
		if (!selected.has(key)) return;
		const next = new Set(selected);
		next.delete(key);
		emit(next);
		closeList();
	}

	function restore(/** @type {string} */ key) {
		add(key);
	}

	function onChipAction(/** @type {{ key: string, state: string }} */ item) {
		if (item.state === 'removed') restore(item.key);
		else remove(item.key);
	}

	function openList() {
		open = true;
		resetVisible();
	}

	function closeList() {
		open = false;
		highlight = 0;
		visibleLimit = PAGE_SIZE;
	}

	function onInput() {
		open = true;
		resetVisible();
		if (!remote) return;
		if (searchTimer) clearTimeout(searchTimer);
		searchTimer = setTimeout(() => {
			dispatch('search', query);
		}, 300);
	}

	function loadMore() {
		if (!hasMore) return;
		visibleLimit = Math.min(visibleLimit + PAGE_SIZE, filtered.length);
	}

	/** @param {Event} e */
	function onListScroll(e) {
		const el = /** @type {HTMLElement} */ (e.currentTarget);
		if (el.scrollTop + el.clientHeight >= el.scrollHeight - 48) {
			loadMore();
		}
	}

	/** @param {KeyboardEvent} e */
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
			if (!open) openList();
			if (visibleOptions.length) {
				highlight = (highlight + 1) % visibleOptions.length;
				if (highlight >= visibleOptions.length - 3) loadMore();
			}
			return;
		}
		if (e.key === 'ArrowUp') {
			e.preventDefault();
			if (!open) openList();
			if (visibleOptions.length) {
				highlight = (highlight - 1 + visibleOptions.length) % visibleOptions.length;
			}
			return;
		}
		if (e.key === 'Enter') {
			if (open && visibleOptions[highlight]) {
				e.preventDefault();
				add(visibleOptions[highlight].key);
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
		/** @param {PointerEvent} e */
		const onDoc = (e) => {
			if (!rootEl?.contains(/** @type {Node} */ (e.target))) closeList();
		};
		document.addEventListener('pointerdown', onDoc);
		return () => {
			document.removeEventListener('pointerdown', onDoc);
			if (searchTimer) clearTimeout(searchTimer);
		};
	});
</script>

<div class="ms-root" bind:this={rootEl} data-variant={variant} data-testid="multiselect" data-label={label || variant}>
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
		data-testid="multiselect-field"
	>
		<input
			bind:this={inputEl}
			class="ms-input"
			type="text"
			data-testid="multiselect-input"
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
			<div class="ms-tray" data-testid="multiselect-tray">
				{#each trayItems as item (item.key + item.state)}
					<button
						type="button"
						class={chipClass(item.state)}
						data-testid="multiselect-chip"
						data-key={item.key}
						data-state={item.state}
						title={item.description || (item.state === 'removed' ? 'Restore' : 'Remove')}
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
		<ul
			class="ms-dropdown"
			id={listId}
			role="listbox"
			data-testid="multiselect-dropdown"
			bind:this={listEl}
			on:scroll={onListScroll}
		>
			{#if remote && query.trim().length > 0 && query.trim().length < 2}
				<li class="ms-empty" role="presentation">{remoteHint}</li>
			{:else if filtered.length === 0}
				<li class="ms-empty" role="presentation" data-testid="multiselect-empty">
					{remote
						? query.trim().length >= 2
							? 'No matches'
							: remoteHint
						: query
							? 'No matches'
							: 'Nothing left to add'}
				</li>
			{:else}
				{#each visibleOptions as opt, i (opt.key)}
					<li role="option" aria-selected={i === highlight}>
						<button
							type="button"
							class="ms-option"
							class:ms-option-active={i === highlight}
							data-testid="multiselect-option"
							data-key={opt.key}
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
				{#if hasMore}
					<li class="ms-empty" role="presentation">Scroll for more…</li>
				{/if}
			{/if}
		</ul>
	{/if}
</div>
