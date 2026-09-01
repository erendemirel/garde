import fs from 'node:fs';

const updates = [
	['e2e/roles/regular/access.spec.ts', '../../helpers/tags', [
		["test.describe('Regular user access control', () => {", "test.describe('Regular user access control', describeTags(TAG.regular, TAG.focused), () => {"]
	]],
	['e2e/roles/regular/dashboard.spec.ts', '../../helpers/tags', [
		["test.describe('Regular user navigation', () => {", "test.describe('Regular user navigation', describeTags(TAG.regular, TAG.dashboard, TAG.focused), () => {"],
		["test.describe('Regular user dashboard', () => {", "test.describe('Regular user dashboard', describeTags(TAG.regular, TAG.dashboard, TAG.focused), () => {"],
		["test.describe('Regular user request update', () => {", "test.describe('Regular user request update', describeTags(TAG.regular, TAG.requestUpdate, TAG.focused), () => {"]
	]],
	['e2e/roles/nav.spec.ts', '../../helpers/tags', [
		["test.describe('Navigation by role', () => {", "test.describe('Navigation by role', describeTags(TAG.nav, TAG.focused), () => {"]
	]],
	['e2e/roles/catalog-modals.spec.ts', '../../helpers/tags', [
		["test.describe('Superuser catalog modals', () => {", "test.describe('Superuser catalog modals', describeTags(TAG.catalog, TAG.superuser, TAG.focused), () => {"],
		["test.describe('Admin catalog modals', () => {", "test.describe('Admin catalog modals', describeTags(TAG.catalog, TAG.admin, TAG.focused), () => {"],
		["test.describe('Visibility manage modals', () => {", "test.describe('Visibility manage modals', describeTags(TAG.catalog, TAG.superuser, TAG.focused), () => {"]
	]],
	['e2e/roles/admin/admin.spec.ts', '../../helpers/tags', [
		["test.describe('Admin users list', () => {", "test.describe('Admin users list', describeTags(TAG.admin, TAG.focused), () => {"]
	]],
	['e2e/roles/admin/admin-user-detail.spec.ts', '../../helpers/tags', [
		["test.describe('Admin user detail', () => {", "test.describe('Admin user detail', describeTags(TAG.admin, TAG.userDetail, TAG.focused), () => {"]
	]],
	['e2e/roles/admin/admin-user-edit.spec.ts', '../../helpers/tags', [
		["test.describe('Admin user detail edits', () => {", "test.describe('Admin user detail edits', describeTags(TAG.admin, TAG.userDetail, TAG.focused), () => {"]
	]],
	['e2e/roles/admin/admin-user-revoke.spec.ts', '../../helpers/tags', [
		["test.describe('Admin revoke and delete', () => {", "test.describe('Admin revoke and delete', describeTags(TAG.admin, TAG.userDetail, TAG.activeSession, TAG.focused), () => {"]
	]],
	['e2e/roles/admin/admin-user-security.spec.ts', '../../helpers/tags', [
		["test.describe('Admin user security actions', () => {", "test.describe('Admin user security actions', describeTags(TAG.admin, TAG.userDetail, TAG.security, TAG.focused), () => {"]
	]],
	['e2e/roles/admin/admin-users-list.spec.ts', '../../helpers/tags', [
		["test.describe('Admin users list interactions', () => {", "test.describe('Admin users list interactions', describeTags(TAG.admin, TAG.focused), () => {"],
		["test.describe('Admin console navigation', () => {", "test.describe('Admin console navigation', describeTags(TAG.admin, TAG.nav, TAG.focused), () => {"]
	]],
	['e2e/roles/admin/admin-catalog.spec.ts', '../../helpers/tags', [
		["test.describe('Admin catalog tabs', () => {", "test.describe('Admin catalog tabs', describeTags(TAG.admin, TAG.catalog, TAG.focused), () => {"]
	]],
	['e2e/roles/admin/admin-catalog-members.spec.ts', '../../helpers/tags', [
		["test.describe('Admin catalog members', () => {", "test.describe('Admin catalog members', describeTags(TAG.admin, TAG.catalog, TAG.focused), () => {"]
	]],
	['e2e/roles/superuser/superuser.spec.ts', '../../helpers/tags', [
		["test.describe('Superuser console', () => {", "test.describe('Superuser console', describeTags(TAG.superuser, TAG.focused), () => {"]
	]],
	['e2e/roles/superuser/users-list.spec.ts', '../../helpers/tags', [
		["test.describe('Users list interactions', () => {", "test.describe('Users list interactions', describeTags(TAG.superuser, TAG.focused), () => {"]
	]],
	['e2e/roles/superuser/superuser-visibility.spec.ts', '../../helpers/tags', [
		["test.describe('Superuser permission visibility', () => {", "test.describe('Superuser permission visibility', describeTags(TAG.superuser, TAG.catalog, TAG.focused), () => {"]
	]],
	['e2e/roles/superuser/superuser-permission.spec.ts', '../../helpers/tags', [
		["test.describe('Superuser permission CRUD', () => {", "test.describe('Superuser permission CRUD', describeTags(TAG.superuser, TAG.catalog, TAG.focused), () => {"]
	]],
	['e2e/roles/superuser/superuser-group.spec.ts', '../../helpers/tags', [
		["test.describe('Superuser group CRUD', () => {", "test.describe('Superuser group CRUD', describeTags(TAG.superuser, TAG.catalog, TAG.focused), () => {"]
	]],
	['e2e/roles/superuser/superuser-catalog-members.spec.ts', '../../helpers/tags', [
		["test.describe('Superuser catalog members', () => {", "test.describe('Superuser catalog members', describeTags(TAG.superuser, TAG.catalog, TAG.focused), () => {"]
	]],
	['e2e/roles/superuser/superuser-admin-management.spec.ts', '../../helpers/tags', [
		["test.describe('Superuser admin-user management', () => {", "test.describe('Superuser admin-user management', describeTags(TAG.superuser, TAG.admin, TAG.focused), () => {"]
	]],
	['e2e/roles/user-detail/user-access.spec.ts', '../../helpers/tags', [
		["test.describe('User access mutate and revert', () => {", "test.describe('User access mutate and revert', describeTags(TAG.userDetail, TAG.superuser, TAG.focused), () => {"]
	]],
	['e2e/roles/user-detail/user-delete.spec.ts', '../../helpers/tags', [
		["test.describe('Delete user', () => {", "test.describe('Delete user', describeTags(TAG.userDetail, TAG.superuser, TAG.focused), () => {"]
	]],
	['e2e/roles/user-detail/user-detail-flows.spec.ts', '../../helpers/tags', [
		["test.describe('User detail edit flows', () => {", "test.describe('User detail edit flows', describeTags(TAG.userDetail, TAG.focused), () => {"]
	]],
	['e2e/roles/user-detail/user-detail-scope.spec.ts', '../../helpers/tags', [
		["test.describe('User detail admin scope', () => {", "test.describe('User detail admin scope', describeTags(TAG.userDetail, TAG.admin, TAG.focused), () => {"]
	]],
	['e2e/roles/user-detail/user-revoke.spec.ts', '../../helpers/tags', [
		["test.describe('Revoke user sessions', () => {", "test.describe('Revoke user sessions', describeTags(TAG.userDetail, TAG.activeSession, TAG.focused), () => {"]
	]],
	['e2e/roles/user-detail/user-security.spec.ts', '../../helpers/tags', [
		["test.describe('User security actions', () => {", "test.describe('User security actions', describeTags(TAG.userDetail, TAG.security, TAG.focused), () => {"]
	]]
];

for (const [file, importPath, replacements] of updates) {
	let content = fs.readFileSync(file, 'utf8');
	if (!content.includes('describeTags')) {
		const m = content.match(/from ['"].*helpers\/fixtures['"];/);
		if (!m) throw new Error(`fixtures import not found in ${file}`);
		const anchor = content.indexOf('\n', m.index + m[0].length - 1);
		const importLine = `import { describeTags, TAG } from '${importPath}';\n`;
		content = content.slice(0, anchor + 1) + importLine + content.slice(anchor + 1);
	}
	for (const [from, to] of replacements) {
		if (!content.includes(from)) throw new Error(`missing ${from} in ${file}`);
		content = content.replace(from, to);
	}
	fs.writeFileSync(file, content);
}

console.log(`Tagged ${updates.length} role spec files`);
