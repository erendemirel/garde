<script>
	import { CircleCheck, CircleX, CircleAlert } from 'lucide-svelte';
	import { formatStatus, getStatusClass } from '$lib/userStatus';

	/** @type {string} */
	export let status = '';
</script>

<span
	class="status-display status-{getStatusClass(status)}"
	data-testid="status-badge"
	data-status={(status || '').toLowerCase()}
>
	<span class="status-icon">
		{#if getStatusClass(status) === 'ok'}
			<CircleCheck size={18} />
		{:else if getStatusClass(status) === 'locked'}
			<CircleX size={18} />
		{:else}
			<CircleAlert size={18} />
		{/if}
	</span>
	<span class="status-text">{formatStatus(status)}</span>
</span>
