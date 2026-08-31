import { writable } from 'svelte/store';

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

export function showToast(message: string, type: ToastType = 'success', durationMs = 5000) {
	if (hideTimer) clearTimeout(hideTimer);
	toast.set({ message, type, visible: true });
	hideTimer = setTimeout(() => {
		toast.update((t) => ({ ...t, visible: false }));
	}, durationMs);
}
