/**
 * Keyboard + ARIA helpers for a simple tablist (WAI-ARIA Tabs pattern).
 * @param {KeyboardEvent} event
 * @param {string[]} tabIds ordered tab ids matching button order
 * @param {string} activeTab
 * @param {(id: string) => void} setTab
 */
export function onTabListKeydown(event, tabIds, activeTab, setTab) {
	const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
	if (!keys.includes(event.key)) return;
	const i = tabIds.indexOf(activeTab);
	if (i < 0) return;
	event.preventDefault();
	let next = i;
	if (event.key === 'ArrowRight') next = (i + 1) % tabIds.length;
	else if (event.key === 'ArrowLeft') next = (i - 1 + tabIds.length) % tabIds.length;
	else if (event.key === 'Home') next = 0;
	else if (event.key === 'End') next = tabIds.length - 1;
	setTab(tabIds[next]);
	queueMicrotask(() => {
		const el = document.getElementById(`tab-${tabIds[next]}`);
		el?.focus();
	});
}
