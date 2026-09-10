import { get, writable, type Writable } from 'svelte/store';
import type { User } from './api';

/** Shared user list for membership/admin panels — avoids re-scanning on every tab mount. */
export const usersCache: Writable<User[]> = writable([]);
export const usersCacheError: Writable<string> = writable('');
export const usersCacheLoading: Writable<boolean> = writable(false);

let usersLoadPromise: Promise<User[]> | null = null;

export function getUsersLoadPromise(): Promise<User[]> | null {
	return usersLoadPromise;
}

export function setUsersLoadPromise(promise: Promise<User[]> | null): void {
	usersLoadPromise = promise;
}

export function invalidateUsersCache(): void {
	usersLoadPromise = null;
	usersCache.set([]);
	usersCacheError.set('');
}

/** Merge users into the shared cache (e.g. after remote search hits). */
export function mergeUsersIntoCache(users: User[]): void {
	if (!users.length) return;
	const byId = new Map(get(usersCache).map((u) => [u.id, u]));
	for (const u of users) byId.set(u.id, u);
	usersCache.set([...byId.values()]);
}

/** Replace the cache with an updated list (e.g. after in-place membership edits). */
export function setUsersCache(users: User[]): void {
	usersCache.set(users);
}
