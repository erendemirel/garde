<script>
	import { createEventDispatcher } from 'svelte';
	import Modal from './Modal.svelte';

	export let open = false;
	export let title = 'Confirm Action';
	export let message = 'Are you sure you want to proceed?';
	export let confirmText = 'Confirm';
	export let cancelText = 'Cancel';
	export let confirmClass = 'btn-secondary';

	const dispatch = createEventDispatcher();

	function handleConfirm() {
		open = false;
		dispatch('confirm');
	}

	function handleCancel() {
		open = false;
		dispatch('cancel');
	}
</script>

<Modal bind:open {title} on:close={handleCancel}>
	<p class="text-text mb-6 whitespace-pre-line">{message}</p>
	<div class="flex gap-3 justify-end">
		<button type="button" class="btn-secondary" on:click={handleCancel}>
			{cancelText}
		</button>
		<button type="button" class={confirmClass} on:click={handleConfirm}>
			{confirmText}
		</button>
	</div>
</Modal>
