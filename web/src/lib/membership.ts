import { updateUser, type User } from './api';

const DEFAULT_CONCURRENCY = 5;

/** Keep only enabled (truthy) entries from a membership map. */
export function enabledKeys(map: Record<string, boolean> | undefined | null): Record<string, boolean> {
	return Object.fromEntries(Object.entries(map || {}).filter(([, enabled]) => enabled));
}

/** Count how many users hold each permission/group key. */
export function countMemberships(
	users: Array<{ permissions?: Record<string, boolean>; groups?: Record<string, boolean> }>,
	mode: 'permissions' | 'groups'
): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const u of users) {
		const map = mode === 'permissions' ? u.permissions : u.groups;
		for (const [key, enabled] of Object.entries(map || {})) {
			if (!enabled) continue;
			counts[key] = (counts[key] || 0) + 1;
		}
	}
	return counts;
}

/** User ids that currently hold the given permission or group. */
export function memberIdsForKey(
	users: Array<{
		id: string;
		permissions?: Record<string, boolean>;
		groups?: Record<string, boolean>;
	}>,
	type: 'permission' | 'group',
	name: string
): Set<string> {
	return new Set(
		users
			.filter((u) => (type === 'permission' ? u.permissions?.[name] : u.groups?.[name]))
			.map((u) => u.id)
	);
}

export function membershipDiff(selected: Set<string>, initial: Set<string>) {
	const adds = [...selected].filter((id) => !initial.has(id));
	const removes = [...initial].filter((id) => !selected.has(id));
	return { adds, removes };
}

/** Run async work over items with a concurrency limit; preserves input order in results. */
export async function mapPool<T, R>(
	items: T[],
	concurrency: number,
	fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
	if (items.length === 0) return [];
	const limit = Math.max(1, Math.min(concurrency, items.length));
	const results = new Array<R>(items.length);
	let next = 0;

	async function worker() {
		while (next < items.length) {
			const i = next++;
			results[i] = await fn(items[i], i);
		}
	}

	await Promise.all(Array.from({ length: limit }, () => worker()));
	return results;
}

type MembershipUser = Pick<User, 'id' | 'permissions' | 'groups'>;

/**
 * Apply add/remove membership for a permission or group across users.
 * Updates mutate the provided user objects in place on success.
 */
export async function applyMembershipUpdates(options: {
	users: MembershipUser[];
	targetType: 'permission' | 'group';
	targetName: string;
	adds: string[];
	removes: string[];
	concurrency?: number;
}): Promise<{ failed: number; lastError: string }> {
	const {
		users,
		targetType,
		targetName,
		adds,
		removes,
		concurrency = DEFAULT_CONCURRENCY
	} = options;
	const byId = new Map(users.map((u) => [u.id, u]));

	type Job = { id: string; kind: 'add' | 'remove' };
	const jobs: Job[] = [
		...adds.map((id) => ({ id, kind: 'add' as const })),
		...removes.map((id) => ({ id, kind: 'remove' as const }))
	];

	let failed = 0;
	let lastError = '';

	await mapPool(jobs, concurrency, async (job) => {
		const user = byId.get(job.id);
		if (!user) return;
		try {
			if (targetType === 'permission') {
				const permissions = { ...enabledKeys(user.permissions) };
				if (job.kind === 'add') permissions[targetName] = true;
				else delete permissions[targetName];
				await updateUser(job.id, { permissions });
				user.permissions = permissions;
			} else {
				const groups = { ...enabledKeys(user.groups) };
				if (job.kind === 'add') groups[targetName] = true;
				else delete groups[targetName];
				await updateUser(job.id, { groups });
				user.groups = groups;
			}
		} catch (e) {
			failed += 1;
			lastError = e instanceof Error ? e.message : 'Update failed';
		}
	});

	return { failed, lastError };
}
