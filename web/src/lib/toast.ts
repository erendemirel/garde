import { writable } from 'svelte/store';
import { browser } from '$app/environment';

export type ToastType = 'success' | 'error';

export type ToastState = {
	message: string;
	type: ToastType;
	visible: boolean;
};

const defaultState: ToastState = {
	message: '',
	type: 'success',
	visible: false
};

export const toast = writable<ToastState>({ ...defaultState });

let hideTimer: ReturnType<typeof setTimeout> | undefined;
let hideAt = 0;

function hideToastNow() {
	hideAt = 0;
	if (hideTimer) clearTimeout(hideTimer);
	toast.update((t) => ({ ...t, visible: false }));
}

function scheduleHide() {
	if (hideTimer) clearTimeout(hideTimer);
	const remaining = hideAt - Date.now();
	if (remaining <= 0) {
		hideToastNow();
		return;
	}
	// Poll in small steps so background-tab timer throttling cannot overshoot by much.
	hideTimer = setTimeout(scheduleHide, Math.min(remaining, 250));
}

if (browser) {
	document.addEventListener('visibilitychange', () => {
		if (document.visibilityState === 'visible' && hideAt > 0 && Date.now() >= hideAt) {
			hideToastNow();
		}
	});
}

export function showToast(message: string, type: ToastType = 'success', durationMs = 5000) {
	hideAt = Date.now() + durationMs;
	toast.set({ message, type, visible: true });
	scheduleHide();
}

export function dismissToast() {
	hideToastNow();
}
