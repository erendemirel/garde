import { get, writable } from 'svelte/store';

/** Shared user list for membership/admin panels — avoids re-scanning on every tab mount. */
export const usersCache = writable(/** @type {import('./api').User[]} */ ([]));
export const usersCacheError = writable('');
export const usersCacheLoading = writable(false);

/** @type {Promise<import('./api').User[]> | null} */
let usersLoadPromise = null;

export function getUsersLoadPromise() {
	return usersLoadPromise;
}

/** @param {Promise<import('./api').User[]> | null} promise */
export function setUsersLoadPromise(promise) {
	usersLoadPromise = promise;
}

export function invalidateUsersCache() {
	usersLoadPromise = null;
	usersCache.set([]);
	usersCacheError.set('');
}

/** Merge users into the shared cache (e.g. after remote search hits). */
export function mergeUsersIntoCache(/** @type {import('./api').User[]} */ users) {
	if (!users.length) return;
	const byId = new Map(get(usersCache).map((u) => [u.id, u]));
	for (const u of users) byId.set(u.id, u);
	usersCache.set([...byId.values()]);
}

/** Replace the cache with an updated list (e.g. after in-place membership edits). */
export function setUsersCache(/** @type {import('./api').User[]} */ users) {
	usersCache.set(users);
}
