import { browser } from '$app/environment';
import { goto } from '$app/navigation';
import { ApiError, isSessionInvalidMessage } from './apiError';
import { clearAuthState } from './stores';

// Use environment variable in production, fallback to /api for development
const API_BASE = import.meta.env.PUBLIC_API_URL || '/api';

const PUBLIC_PATHS = new Set(['/', '/register', '/forgot-password']);
const CREDENTIAL_401_ENDPOINTS = new Set(['/login']);

type ApiResponse<T> = { data: T } | { error: { message: string } };

function isPublicLocation() {
	if (!browser) return true;
	return PUBLIC_PATHS.has(window.location.pathname);
}

/** Bumped when the session is cleared so in-flight refreshSession calls cannot repopulate stores. */
let sessionGeneration = 0;

export function getSessionGeneration() {
	return sessionGeneration;
}

/** Clear client auth state and invalidate any in-flight session refresh. */
export function invalidateSession() {
	sessionGeneration++;
	clearAuthState();
}

function handleExpiredSession() {
	invalidateSession();
	if (browser && !isPublicLocation()) {
		goto('/');
	}
}

/** Only true session/auth failures should clear client state — not out-of-scope 401s. */
function shouldExpireSession(status: number, path: string, message: string): boolean {
	if (status !== 401 || CREDENTIAL_401_ENDPOINTS.has(path)) return false;
	if (path.endsWith('/users/me')) return true;
	return isSessionInvalidMessage(message);
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
	const path = endpoint.split('?')[0];
	const res = await fetch(`${API_BASE}${endpoint}`, {
		...options,
		credentials: 'include',
		headers: {
			'Content-Type': 'application/json',
			...options.headers
		}
	});

	let json: ApiResponse<T>;
	try {
		json = await res.json();
	} catch {
		if (shouldExpireSession(res.status, path, '')) {
			handleExpiredSession();
		}
		throw new ApiError(
			res.ok ? 'Invalid response from server' : `Request failed (${res.status})`,
			res.status
		);
	}

	const errorMessage = 'error' in json ? json.error.message : '';

	if (shouldExpireSession(res.status, path, errorMessage)) {
		handleExpiredSession();
	}

	if ('error' in json) {
		throw new ApiError(json.error.message, res.status);
	}

	if (!res.ok) {
		throw new ApiError(`Request failed (${res.status})`, res.status);
	}

	return json.data;
}

// Auth
export const login = (email: string, password: string, mfa_code?: string) =>
	request<{ session_id: string }>('/login', {
		method: 'POST',
		body: JSON.stringify({ email, password, mfa_code })
	});

export const logout = () => request('/logout', { method: 'POST' });

export const register = (email: string, password: string) =>
	request<{ user_id: string }>('/users', {
		method: 'POST',
		body: JSON.stringify({ email, password })
	});

// Password
export const requestOtp = (email: string) =>
	request('/users/password/otp', {
		method: 'POST',
		body: JSON.stringify({ email })
	});

export const resetPassword = (email: string, otp: string, new_password: string, mfa_code?: string) =>
	request('/users/password/reset', {
		method: 'POST',
		body: JSON.stringify({ email, otp, new_password, mfa_code })
	});

export const changePassword = (old_password: string, new_password: string, mfa_code?: string) =>
	request('/users/password/change', {
		method: 'POST',
		body: JSON.stringify({ old_password, new_password, mfa_code })
	});

// User
export interface User {
	id: string;
	email: string;
	status: string;
	mfa_enabled: boolean;
	mfa_enforced: boolean;
	permissions: Record<string, boolean>;
	groups: Record<string, boolean>;
	created_at: string;
	updated_at: string;
	last_login: string;
	is_superuser?: boolean;
	is_admin?: boolean;
	pending_updates?: {
		requested_at: string;
		fields: {
			permissions_add?: string[];
			permissions_remove?: string[];
			groups_add?: string[];
			groups_remove?: string[];
		};
	};
}

export const getMe = () => request<User>('/users/me');

export const requestUpdate = (updates: {
	permissions_add?: string[];
	permissions_remove?: string[];
	groups_add?: string[];
	groups_remove?: string[];
}) =>
	request('/users/request-update-from-admin', {
		method: 'POST',
		body: JSON.stringify({ updates })
	});

// MFA
export const setupMfa = () => request<{ secret: string; qr_code_url: string }>('/users/mfa/setup', { 
	method: 'POST',
	body: JSON.stringify({})
});

export const verifyMfa = (code: string, email?: string) =>
	request('/users/mfa/verify', {
		method: 'POST',
		body: JSON.stringify({ code, email })
	});

export const disableMfa = (mfa_code: string) =>
	request('/users/mfa/disable', {
		method: 'POST',
		body: JSON.stringify({ mfa_code })
	});

// Admin
export const listUsers = (params?: {
	q?: string;
	sort?: string;
	order?: string;
	page?: number;
	limit?: number;
}) => {
	const sp = new URLSearchParams();
	if (params?.q) sp.set('q', params.q);
	if (params?.sort) sp.set('sort', params.sort);
	if (params?.order) sp.set('order', params.order);
	if (params?.page) sp.set('page', String(params.page));
	if (params?.limit) sp.set('limit', String(params.limit));
	const qs = sp.toString();
	return request<{ users: User[]; total?: number; page?: number; limit?: number }>(
		`/users${qs ? `?${qs}` : ''}`
	);
};

export const getUser = (user_id: string) => request<User>(`/users/${user_id}`);

export const updateUser = (
	user_id: string,
	updates: {
		status?: string;
		mfa_enforced?: boolean;
		permissions?: Record<string, boolean>;
		groups?: Record<string, boolean>;
		approve_update?: boolean;
		reject_update?: boolean;
	}
) =>
	request<User>(`/users/${user_id}`, {
		method: 'PUT',
		body: JSON.stringify(updates)
	});

export const revokeSessions = (user_id: string, mfa_code?: string) =>
	request('/sessions/revoke', {
		method: 'POST',
		body: JSON.stringify({ user_id, mfa_code })
	});

export const deleteUser = (user_id: string) =>
	request(`/users/${user_id}`, {
		method: 'DELETE'
	});

// Config
export interface PermissionInfo {
	key: string;
	name: string;
	description: string;
}

export interface GroupInfo {
	key: string;
	name: string;
	description: string;
}

export const listPermissions = () => request<PermissionInfo[]>('/permissions');

export const listGroups = () => request<GroupInfo[]>('/groups');

// Superuser-only endpoints
export const createPermission = (name: string, definition: string) =>
	request<PermissionInfo>('/admin/permissions', {
		method: 'POST',
		body: JSON.stringify({ name, definition })
	});

export const updatePermission = (permission_name: string, definition: string) =>
	request<PermissionInfo>(`/admin/permissions/${permission_name}`, {
		method: 'PUT',
		body: JSON.stringify({ definition })
	});

export const deletePermission = (permission_name: string) =>
	request(`/admin/permissions/${permission_name}`, {
		method: 'DELETE'
	});

export const createGroup = (name: string, definition: string) =>
	request<GroupInfo>('/admin/groups', {
		method: 'POST',
		body: JSON.stringify({ name, definition })
	});

export const updateGroup = (group_name: string, definition: string) =>
	request<GroupInfo>(`/admin/groups/${group_name}`, {
		method: 'PUT',
		body: JSON.stringify({ definition })
	});

export const deleteGroup = (group_name: string) =>
	request(`/admin/groups/${group_name}`, {
		method: 'DELETE'
	});

export const addPermissionVisibility = (permission_name: string, group_name: string) =>
	request('/admin/permissions/visibility', {
		method: 'POST',
		body: JSON.stringify({ permission_name, group_name })
	});

export const removePermissionVisibility = (permission_name: string, group_name: string) =>
	request('/admin/permissions/visibility', {
		method: 'DELETE',
		body: JSON.stringify({ permission_name, group_name })
	});

export const getAllPermissionVisibility = () =>
	request<Record<string, string[]>>('/admin/permissions/visibility');

export const getAdminUserManagement = () =>
	request<Record<string, string[]>>('/admin/users/management');

