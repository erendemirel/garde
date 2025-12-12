<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { getMe, logout, listUsers, listPermissions } from '$lib/api';
	import { user, isAdmin, isSuperuser } from '$lib/stores';
	import { LogOut } from 'lucide-svelte';

	let loading = true;

	onMount(async () => {
		try {
			const me = await getMe();
			user.set(me);
			
			// Check if MFA is enforced but not set up - redirect to MFA setup
			if (me.mfa_enforced && !me.mfa_enabled) {
				// Only redirect if not already on MFA page
				if (!$page.url.pathname.startsWith('/mfa')) {
					loading = false;
					goto('/mfa');
					return;
				}
			}
			
			// Set admin and superuser flags from user response
			isSuperuser.set(me.is_superuser || false);
			isAdmin.set(me.is_admin || false);
		} catch {
			goto('/');
		}
		loading = false;
	});

	async function handleLogout() {
		try {
			await logout();
		} catch {}
		user.set(null);
		isAdmin.set(false);
		isSuperuser.set(false);
		goto('/');
	}
</script>

{#if loading}
	<div class="container-base max-w-md mx-auto pt-32 text-center text-muted">
		<p>Loading...</p>
	</div>
{:else if $user}
	<nav class="navbar">
		<a href="/dashboard" class="text-lg font-semibold text-accent">garde</a>
		<div class="nav-links">
			<a href="/dashboard" class="hover:text-accent transition-all duration-150 ease-out hover:-translate-y-0.5 hover:shadow-md">Dashboard</a>
			{#if $isSuperuser}
				<a href="/superuser" class="hover:text-accent transition-all duration-150 ease-out hover:-translate-y-0.5 hover:shadow-md">Superuser</a>
				<a href="/admin" class="hover:text-accent transition-all duration-150 ease-out hover:-translate-y-0.5 hover:shadow-md">Admin</a>
			{:else if $isAdmin}
				<a href="/admin" class="hover:text-accent transition-all duration-150 ease-out hover:-translate-y-0.5 hover:shadow-md">Admin</a>
			{/if}
			<button class="btn-secondary" on:click={handleLogout}>
				<LogOut size={18} />
				Logout
			</button>
		</div>
	</nav>
	<slot />
{/if}

