<script>
	import { toast } from '$lib/toast';
</script>

{#if $toast.visible}
	<div
		class="toast"
		class:toast-success={$toast.type === 'success'}
		class:toast-error={$toast.type === 'error'}
		role="status"
		aria-live={$toast.type === 'error' ? 'assertive' : 'polite'}
		aria-atomic="true"
	>
		{$toast.message}
	</div>
{/if}
