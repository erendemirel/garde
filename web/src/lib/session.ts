import { getMe, getSessionGeneration } from './api';
import { user, isAdmin, isSuperuser } from './stores';

/** Refetch /api/users/me and sync role flags — use after mutations that affect the signed-in user. */
export async function refreshSession() {
	const generation = getSessionGeneration();
	const me = await getMe();
	if (generation !== getSessionGeneration()) return null;
	user.set(me);
	isSuperuser.set(!!me.is_superuser);
	isAdmin.set(!!me.is_admin);
	return me;
}
