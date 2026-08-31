<script>
	import { createEventDispatcher, tick } from 'svelte';

	export let open = false;
	export let title = '';
	export let labelledBy = 'modal-title';
	export let wide = false;
	/** When true, prefer focusing the dialog shell instead of the first input (keeps search closed). */
	export let preferDialogFocus = false;

	const dispatch = createEventDispatcher();

	function close() {
		open = false;
		dispatch('close');
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
		<button
			type="button"
			class="absolute inset-0 h-full w-full cursor-default bg-transparent"
			aria-label="Close dialog"
			on:click={close}
		></button>
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
					<slot name="header-end" />
				</div>
			{/if}
			<div class="modal-body">
				<slot />
			</div>
			{#if $$slots.footer}
				<div class="modal-footer">
					<slot name="footer" />
				</div>
			{/if}
		</div>
	</div>
{/if}
