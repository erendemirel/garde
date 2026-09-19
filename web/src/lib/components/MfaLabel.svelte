<script>
	import { formatMfaLabel, getMfaKind, mfaToneClass } from '$lib/userStatus';

	/** @type {{ enabled?: boolean, enforced?: boolean, compact?: boolean }} */
	let { enabled = false, enforced = false, compact = false } = $props();

	let kind = $derived(getMfaKind(enabled, enforced));
	let label = $derived(formatMfaLabel(kind, compact));
	let full = $derived(formatMfaLabel(kind, false));
</script>

<span class={mfaToneClass(kind)} title={full}>{label}</span>
