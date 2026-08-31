<script>
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { getMe, logout } from '$lib/api';
	import { user, isAdmin, isSuperuser, clearAuthState } from '$lib/stores';
	import { LogOut } from 'lucide-svelte';

	/** Skip full-screen load when navigating within an already-authenticated session. */
	let loading = !$user;
	let bootError = '';

	$: mfaBlocked = !!$user?.mfa_enforced && !$user?.mfa_enabled;
	$: path = $page.url.pathname;

	$: if (browser && $user && mfaBlocked && !path.startsWith('/mfa')) {
		goto('/mfa');
	}

	onMount(async () => {
		bootError = '';
		try {
			const me = await getMe();
			user.set(me);
			isSuperuser.set(!!me.is_superuser);
			isAdmin.set(!!me.is_admin);
		} catch (e) {
			clearAuthState();
			bootError = e instanceof Error ? e.message : 'Session expired';
			goto('/');
		}
		loading = false;
	});

	async function handleLogout() {
		try {
			await logout();
		} catch {}
		clearAuthState();
		goto('/');
	}
</script>

{#if loading}
	<div class="container-base max-w-md mx-auto pt-32 text-center text-muted" aria-live="polite">
		<p>Loading session…</p>
	</div>
{:else if $user}
	<nav class="navbar">
		{#if mfaBlocked}
			<span class="text-lg font-semibold text-accent">garde</span>
		{:else}
			<a href="/dashboard" class="text-lg font-semibold text-accent no-underline">garde</a>
		{/if}
		<div class="nav-links">
			{#if !mfaBlocked}
				<a
					href="/dashboard"
					class="nav-link"
					class:nav-link-active={path.startsWith('/dashboard')}
					aria-current={path.startsWith('/dashboard') ? 'page' : undefined}
				>Dashboard</a>
				{#if $isSuperuser}
					<a
						href="/superuser"
						class="nav-link"
						class:nav-link-active={path.startsWith('/superuser')}
						aria-current={path.startsWith('/superuser') ? 'page' : undefined}
					>Superuser</a>
				{:else if $isAdmin}
					<a
						href="/admin"
						class="nav-link"
						class:nav-link-active={path.startsWith('/admin')}
						aria-current={path.startsWith('/admin') ? 'page' : undefined}
					>Admin</a>
				{/if}
			{/if}
			<button class="btn-secondary" type="button" on:click={handleLogout}>
				<LogOut size={18} />
				Logout
			</button>
		</div>
	</nav>
	{#if mfaBlocked && !path.startsWith('/mfa')}
		<div class="container-base max-w-md mx-auto pt-32 text-center text-muted" aria-live="polite">
			<p>Redirecting to MFA setup…</p>
		</div>
	{:else}
		<slot />
	{/if}
{:else if bootError}
	<div class="container-base max-w-md mx-auto pt-32 text-center">
		<p class="error">{bootError}</p>
		<a href="/" class="btn-secondary mt-4 inline-flex">Sign in</a>
	</div>
{/if}
