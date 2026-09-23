<script>
	/** @type {{ size?: number, strokeWidth?: number, class?: string }} */
	let { size = 24, strokeWidth = 2, class: className = '' } = $props();
</script>

<svg
	xmlns="http://www.w3.org/2000/svg"
	width={size}
	height={size}
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width={strokeWidth}
	stroke-linecap="round"
	stroke-linejoin="round"
	class={className}
	aria-hidden="true"
>
	<path
		d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
	/>
	<rect width="8" height="6" x="8" y="11.5" rx="1" />
	<path d="M10.5 11.5V9.5a1.5 1.5 0 0 1 3 0v2" />
</svg>
