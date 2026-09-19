<script>
	import { onMount } from 'svelte';
	import { X } from '@lucide/svelte';

	/** @type {{
	 *   options?: { key: string, name: string, description?: string }[],
	 *   selected?: Set<string>,
	 *   initial?: Set<string>,
	 *   variant?: 'permission' | 'group' | 'scope',
	 *   placeholder?: string,
	 *   label?: string,
	 *   remote?: boolean,
	 *   remoteHint?: string,
	 *   onChange?: (next: Set<string>) => void,
	 *   onSearch?: (query: string) => void
	 * }} */
	let {
		options = [],
		selected = $bindable(new Set()),
		initial = new Set(),
		variant = 'permission',
		placeholder = 'Search to add…',
		label = '',
		remote = false,
		remoteHint = 'Type at least 2 characters to search…',
		onChange,
		onSearch
	} = $props();

	const PAGE_SIZE = 25;
	const listId = `ms-list-${Math.random().toString(36).slice(2, 9)}`;

	let query = $state('');
	let open = $state(false);
	let highlight = $state(0);
	let visibleLimit = $state(PAGE_SIZE);
	/** @type {HTMLElement | null} */
	let rootEl = $state(null);
	/** @type {HTMLInputElement | null} */
	let inputEl = $state(null);
	/** @type {HTMLUListElement | null} */
	let listEl = $state(null);
	/** @type {ReturnType<typeof setTimeout> | undefined} */
	let searchTimer;

	let selectedStyle = $derived(
		variant === 'group' ? 'badge-group' : variant === 'scope' ? 'badge-scope' : 'badge-permission'
	);

	/** Selected chips, then pending removals (still visible until undo). */
	let trayItems = $derived([
		...options.filter((o) => selected.has(o.key)).map((o) => ({ ...o, state: pendingState(o.key) })),
		...options
			.filter((o) => !selected.has(o.key) && initial.has(o.key))
			.map((o) => ({ ...o, state: 'removed' }))
	]);

	/** Addable options: not selected; pending removals stay in the tray only. */
	let filtered = $derived(
		options.filter((o) => {
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
		})
	);

	let visibleOptions = $derived(filtered.slice(0, visibleLimit));
	let hasMore = $derived(visibleLimit < filtered.length);

	$effect(() => {
		if (highlight >= visibleOptions.length) {
			highlight = Math.max(0, visibleOptions.length - 1);
		}
	});

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
		onChange?.(next);
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
			onSearch?.(query);
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
			onfocus={openList}
			oninput={onInput}
			onkeydown={onKeydown}
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
						onclick={() => onChipAction(item)}
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
			onscroll={onListScroll}
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
							onclick={() => add(opt.key)}
							onmouseenter={() => (highlight = i)}
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
