import { get } from 'svelte/store';
import { listUsers, type User } from './api';
import { mapPool } from './membership';
import {
	getUsersLoadPromise,
	invalidateUsersCache,
	mergeUsersIntoCache,
	setUsersCache,
	setUsersLoadPromise,
	usersCache,
	usersCacheError,
	usersCacheLoading
} from './usersCache';

export {
	invalidateUsersCache,
	mergeUsersIntoCache,
	setUsersCache,
	usersCache,
	usersCacheError,
	usersCacheLoading
};

const PAGE_LIMIT = 100;
/** Parallel page fetches after the first page (which reveals total). */
const PAGE_FETCH_CONCURRENCY = 5;

/** Load every user page (limit capped at 100 by the API). Pages after the first load in parallel. */
export async function loadUsersAllPages(params?: {
	q?: string;
	sort?: string;
	order?: string;
	signal?: AbortSignal;
}): Promise<User[]> {
	const { signal, ...listParams } = params || {};
	const throwIfAborted = () => {
		if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
	};

	throwIfAborted();
	const first = await listUsers({
		...listParams,
		page: 1,
		limit: PAGE_LIMIT
	});
	throwIfAborted();

	const all: User[] = [...(first.users || [])];
	const total = first.total ?? all.length;
	if (all.length >= total || all.length < PAGE_LIMIT) {
		return all;
	}

	const lastPage = Math.ceil(total / PAGE_LIMIT);
	const pageNumbers = Array.from({ length: lastPage - 1 }, (_, i) => i + 2);
	const batches = await mapPool(pageNumbers, PAGE_FETCH_CONCURRENCY, async (page) => {
		throwIfAborted();
		const res = await listUsers({
			...listParams,
			page,
			limit: PAGE_LIMIT
		});
		return res.users || [];
	});

	for (const batch of batches) {
		all.push(...batch);
	}
	return all;
}

/**
 * Ensure the shared users cache is populated. Concurrent callers share one in-flight request.
 * Pass `force: true` to refetch after mutations that may have partial failures.
 */
export function ensureUsersCache(options?: { force?: boolean }): Promise<User[]> {
	const force = options?.force === true;
	const existing = getUsersLoadPromise();
	if (!force && existing) return existing;
	if (!force && get(usersCache).length > 0) {
		return Promise.resolve(get(usersCache));
	}

	usersCacheLoading.set(true);
	usersCacheError.set('');
	const promise = loadUsersAllPages()
		.then((users) => {
			usersCache.set(users);
			usersCacheError.set('');
			return users;
		})
		.catch((e) => {
			const msg = e instanceof Error ? e.message : 'Failed to load users';
			usersCache.set([]);
			usersCacheError.set(msg);
			setUsersLoadPromise(null);
			throw e instanceof Error ? e : new Error(msg);
		})
		.finally(() => {
			usersCacheLoading.set(false);
		});

	setUsersLoadPromise(promise);
	return promise;
}

/** Search users for membership pickers — always paginated. */
export async function searchUsers(q: string, limit = 50): Promise<User[]> {
	const trimmed = q.trim();
	if (!trimmed) return [];
	const res = await listUsers({ q: trimmed, page: 1, limit });
	return res.users || [];
}
