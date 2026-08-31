<script>
	import { formatMfaLabel, getMfaKind, mfaToneClass } from '$lib/userStatus';

	/** @type {boolean} */
	export let enabled = false;
	/** @type {boolean} */
	export let enforced = false;
	/** Prefer shorter labels on narrow tables */
	export let compact = false;

	$: kind = getMfaKind(enabled, enforced);
	$: label = formatMfaLabel(kind, compact);
	$: full = formatMfaLabel(kind, false);
</script>

<span class={mfaToneClass(kind)} title={full}>{label}</span>
