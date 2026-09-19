<script>
	/**
	 * Lucide `user-group` (https://lucide.dev/icons/user-group, since Lucide 1.42.0).
	 * garde is on lucide-svelte@0.556 (Svelte 4). The current package @lucide/svelte@1.47+
	 * has this icon but requires Svelte 5 — local backport until that upgrade.
	 */
	export let size = 24;
	/** @type {string} */
	let className = '';
	export { className as class };
</script>

<svg
	xmlns="http://www.w3.org/2000/svg"
	width={size}
	height={size}
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width="2"
	stroke-linecap="round"
	stroke-linejoin="round"
	class={className}
	aria-hidden="true"
	{...$$restProps}
>
	<path d="M17 21v-1a2 2 0 0 0-2-2H9a2 2 0 0 0-2 2v1" />
	<path d="M19 10h1a2 2 0 0 1 2 2v1" />
	<path d="M5 10H4a2 2 0 0 0-2 2v1" />
	<circle cx="12" cy="11" r="3" />
	<circle cx="18" cy="4" r="2" />
	<circle cx="6" cy="4" r="2" />
</svg>
