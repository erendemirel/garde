<script>
	import { toast, dismissToast } from '$lib/toast';
	import { X } from 'lucide-svelte';
</script>

{#if $toast.visible}
	<div
		class="toast flex items-start gap-2"
		class:toast-success={$toast.type === 'success'}
		class:toast-error={$toast.type === 'error'}
		role="status"
		aria-live={$toast.type === 'error' ? 'assertive' : 'polite'}
		aria-atomic="true"
		data-testid="toast"
		data-toast-type={$toast.type}
	>
		<span class="flex-1 min-w-0">{$toast.message}</span>
		<button
			type="button"
			class="shrink-0 rounded p-0.5 opacity-70 hover:opacity-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
			aria-label="Dismiss notification"
			data-testid="toast-dismiss"
			on:click={dismissToast}
		>
			<X size={16} />
		</button>
	</div>
{/if}
