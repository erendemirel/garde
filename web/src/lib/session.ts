import { getMe } from './api';
import { user, isAdmin, isSuperuser } from './stores';

/** Refetch /api/users/me and sync role flags — use after mutations that affect the signed-in user. */
export async function refreshSession() {
	const me = await getMe();
	user.set(me);
	isSuperuser.set(!!me.is_superuser);
	isAdmin.set(!!me.is_admin);
	return me;
}
