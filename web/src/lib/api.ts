// Use environment variable in production, fallback to /api for development
const API_BASE = import.meta.env.PUBLIC_API_URL || '/api';

type ApiResponse<T> = { data: T } | { error: { message: string } };

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
	const res = await fetch(`${API_BASE}${endpoint}`, {
		...options,
		credentials: 'include',
		headers: {
			'Content-Type': 'application/json',
			...options.headers
		}
	});

	const json: ApiResponse<T> = await res.json();

	if ('error' in json) {
		throw new Error(json.error.message);
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
			permissions?: Record<string, boolean>;
			groups?: Record<string, boolean>;
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
export const listUsers = () => request<{ users: User[] }>('/users');

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

export const getAllGroupUsers = () =>
	request<Record<string, string[]>>('/admin/groups/users');

export const getAdminUserManagement = () =>
	request<Record<string, string[]>>('/admin/users/management');

