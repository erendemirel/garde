import { listUsers, type User } from './api';

const PAGE_LIMIT = 100;

/** Load every user page (limit capped at 100 by the API). Prefer for one-shot membership scans, not route mount. */
export async function loadUsersAllPages(params?: {
	q?: string;
	sort?: string;
	order?: string;
}): Promise<User[]> {
	const all: User[] = [];
	let page = 1;
	let total = Infinity;

	while (all.length < total) {
		const res = await listUsers({
			...params,
			page,
			limit: PAGE_LIMIT
		});
		const batch = res.users || [];
		total = res.total ?? batch.length;
		all.push(...batch);
		if (batch.length === 0 || batch.length < PAGE_LIMIT) break;
		page += 1;
	}

	return all;
}

/** Search users for membership pickers — always paginated. */
export async function searchUsers(q: string, limit = 50): Promise<User[]> {
	const trimmed = q.trim();
	if (!trimmed) return [];
	const res = await listUsers({ q: trimmed, page: 1, limit });
	return res.users || [];
}
