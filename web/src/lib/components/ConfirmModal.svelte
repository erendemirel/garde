<script>
	import { createEventDispatcher } from 'svelte';
	
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

	function handleKeydown(event) {
		if (event.key === 'Escape') {
			handleCancel();
		}
	}
</script>

{#if open}
	<div 
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/60" 
		on:click={handleCancel}
		on:keydown={handleKeydown}
		role="dialog" 
		aria-modal="true" 
		aria-labelledby="modal-title"
		tabindex="-1"
	>
		<div class="card max-w-md w-full mx-4 border-2 border-borderc shadow-xl" on:click|stopPropagation role="document">
			<h2 id="modal-title" class="text-xl font-bold text-accent mb-2">{title}</h2>
			<p class="text-text mb-6">{message}</p>
			<div class="flex gap-3 justify-end">
				<button class="btn-secondary" on:click={handleCancel}>
					{cancelText}
				</button>
				<button class={confirmClass} on:click={handleConfirm}>
					{confirmText}
				</button>
			</div>
		</div>
	</div>
{/if}

