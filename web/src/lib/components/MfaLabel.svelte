<script>
	import { ShieldAlert, ShieldCheck, ShieldX } from '@lucide/svelte';
	import { formatMfaLabel, getMfaKind, mfaToneClass } from '$lib/userStatus';

	/** @type {{ enabled?: boolean, enforced?: boolean, compact?: boolean }} */
	let { enabled = false, enforced = false, compact = false } = $props();

	let kind = $derived(getMfaKind(enabled, enforced));
	let label = $derived(formatMfaLabel(kind, compact));
	let full = $derived(formatMfaLabel(kind, false));
</script>

<span class="status-display {mfaToneClass(kind)}" title={full}>
	<span class="status-icon">
		{#if kind === 'enforced-missing'}
			<ShieldX size={18} />
		{:else if kind === 'none'}
			<ShieldAlert size={18} />
		{:else}
			<ShieldCheck size={18} />
		{/if}
	</span>
	<span class="status-text">{label}</span>
</span>
