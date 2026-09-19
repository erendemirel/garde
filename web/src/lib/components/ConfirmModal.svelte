<script>
	import Modal from './Modal.svelte';

	/** @type {{
	 *   open?: boolean,
	 *   title?: string,
	 *   message?: string,
	 *   confirmText?: string,
	 *   cancelText?: string,
	 *   confirmClass?: string,
	 *   onConfirm?: () => void,
	 *   onCancel?: () => void
	 * }} */
	let {
		open = $bindable(false),
		title = 'Confirm Action',
		message = 'Are you sure you want to proceed?',
		confirmText = 'Confirm',
		cancelText = 'Cancel',
		confirmClass = 'btn-secondary',
		onConfirm,
		onCancel
	} = $props();

	function handleConfirm() {
		// Dispatch first, then defer close so the activating click finishes before unmount
		// (Playwright otherwise sees click hangs or fall-through under remount).
		onConfirm?.();
		queueMicrotask(() => {
			open = false;
		});
	}

	function handleCancel() {
		onCancel?.();
		queueMicrotask(() => {
			open = false;
		});
	}
</script>

<Modal bind:open {title} onClose={handleCancel}>
	<p class="text-text mb-6 whitespace-pre-line" data-testid="confirm-modal-message">{message}</p>
	<div class="flex gap-3 justify-end">
		<button type="button" class="btn-secondary" data-testid="confirm-modal-cancel" onclick={handleCancel}>
			{cancelText}
		</button>
		<button type="button" class={confirmClass} data-testid="confirm-modal-confirm" onclick={handleConfirm}>
			{confirmText}
		</button>
	</div>
</Modal>
