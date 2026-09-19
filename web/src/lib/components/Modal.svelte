<script>
	import { tick } from 'svelte';

	/** @type {{
	 *   open?: boolean,
	 *   title?: string,
	 *   labelledBy?: string,
	 *   wide?: boolean,
	 *   preferDialogFocus?: boolean,
	 *   dismissible?: boolean,
	 *   onClose?: () => void,
	 *   children?: import('svelte').Snippet,
	 *   headerEnd?: import('svelte').Snippet,
	 *   footer?: import('svelte').Snippet
	 * }} */
	let {
		open = $bindable(false),
		title = '',
		labelledBy = 'modal-title',
		wide = false,
		preferDialogFocus = false,
		dismissible = true,
		onClose,
		children,
		headerEnd,
		footer
	} = $props();

	function close() {
		if (!dismissible) return;
		open = false;
		onClose?.();
	}

	/** @param {HTMLElement} node */
	function dialogAction(node) {
		const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;

		function focusables() {
			return [...node.querySelectorAll(
				'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
			)].filter((el) => el instanceof HTMLElement);
		}

		tick().then(() => {
			const items = focusables();
			if (preferDialogFocus) {
				node.focus();
				return;
			}
			const preferred = items.find((el) =>
				['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName)
			);
			(preferred || items[0] || node).focus();
		});

		/** @param {KeyboardEvent} e */
		function onKey(e) {
			if (e.key === 'Escape') {
				e.preventDefault();
				close();
				return;
			}
			if (e.key !== 'Tab') return;
			const items = focusables();
			if (items.length === 0) {
				e.preventDefault();
				return;
			}
			const first = items[0];
			const last = items[items.length - 1];
			if (e.shiftKey && document.activeElement === first) {
				e.preventDefault();
				last.focus();
			} else if (!e.shiftKey && document.activeElement === last) {
				e.preventDefault();
				first.focus();
			}
		}

		node.addEventListener('keydown', onKey);
		return {
			destroy() {
				node.removeEventListener('keydown', onKey);
				previous?.focus();
			}
		};
	}
</script>

{#if open}
	<div class="modal-overlay">
		{#if dismissible}
			<button
				type="button"
				class="absolute inset-0 h-full w-full cursor-default bg-transparent"
				aria-label="Close dialog"
				onclick={close}
			></button>
		{:else}
			<div class="absolute inset-0 h-full w-full bg-transparent" aria-hidden="true"></div>
		{/if}
		<div
			class="modal-content relative z-10"
			class:modal-content-wide={wide}
			role="dialog"
			aria-modal="true"
			aria-labelledby={title ? labelledBy : undefined}
			tabindex="-1"
			use:dialogAction
		>
			{#if title}
				<div class="mb-4 flex shrink-0 items-center justify-between gap-3">
					<h2 id={labelledBy} class="section-title">{title}</h2>
					{#if headerEnd}
						{@render headerEnd()}
					{/if}
				</div>
			{/if}
			<div class="modal-body">
				{#if children}
					{@render children()}
				{/if}
			</div>
			{#if footer}
				<div class="modal-footer">
					{@render footer()}
				</div>
			{/if}
		</div>
	</div>
{/if}
