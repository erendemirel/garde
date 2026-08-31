export type StatusKind = 'ok' | 'locked' | 'pending';

export function getStatusClass(status: string | undefined | null): StatusKind {
	const s = (status || '').toLowerCase();
	if (s === 'ok') return 'ok';
	if (s.includes('locked') || s.includes('disabled') || s.includes('rejected')) return 'locked';
	if (s.includes('pending')) return 'pending';
	return 'pending';
}

export function formatStatus(status: string | undefined | null): string {
	const s = (status || '').toLowerCase();
	if (s === 'ok') return 'OK';
	if (s === 'pending admin approval') return 'Pending approval by an admin';
	if (s === 'admin approval rejected') return 'Approval rejected by an admin';
	if (s === 'locked by admin') return 'Locked by an admin';
	if (s === 'locked by security') return 'Locked by security';
	return status || 'Unknown';
}

export type MfaKind = 'enforced-setup' | 'setup-only' | 'enforced-missing' | 'none';

export function getMfaKind(enabled: boolean | undefined, enforced: boolean | undefined): MfaKind {
	if (enabled && enforced) return 'enforced-setup';
	if (enabled) return 'setup-only';
	if (enforced) return 'enforced-missing';
	return 'none';
}

export function formatMfaLabel(kind: MfaKind, compact = false): string {
	switch (kind) {
		case 'enforced-setup':
			return compact ? 'Enforced + set up' : 'Enforced and set up';
		case 'setup-only':
			return compact ? 'Set up' : 'Set up although not enforced';
		case 'enforced-missing':
			return compact ? 'Required' : 'Enforced but not set up';
		default:
			return compact ? 'Off' : 'Not enforced and not set up';
	}
}

export function mfaToneClass(kind: MfaKind): string {
	switch (kind) {
		case 'enforced-setup':
			return 'text-blue-600';
		case 'setup-only':
			return 'text-green-700';
		case 'enforced-missing':
			return 'text-red-600';
		default:
			return 'text-orange-500';
	}
}
