<script>
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { logout } from '$lib/api';
	import { user, isAdmin, isSuperuser, clearAuthState } from '$lib/stores';
	import { refreshSession } from '$lib/session';
	import { LogOut } from 'lucide-svelte';

	/** Block chrome until the session is verified on first mount. */
	let loading = true;
	let bootError = '';

	$: mfaBlocked = !!$user?.mfa_enforced && !$user?.mfa_enabled;
	$: path = $page.url.pathname;

	$: if (browser && $user && mfaBlocked && !path.startsWith('/mfa')) {
		goto('/mfa');
	}

	$: if (browser && !loading && !$user && !bootError) {
		goto('/');
	}

	onMount(async () => {
		bootError = '';
		try {
			await refreshSession();
		} catch (e) {
			clearAuthState();
			bootError = e instanceof Error ? e.message : 'Session expired';
			goto('/');
		} finally {
			loading = false;
		}
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
	<div
		class="container-base max-w-md mx-auto pt-32 text-center text-muted"
		aria-live="polite"
		data-testid="session-loading"
	>
		<p>Loading session…</p>
	</div>
{:else if $user}
	<nav class="navbar" data-testid="app-nav">
		{#if mfaBlocked}
			<span class="text-lg font-semibold text-accent">garde</span>
		{:else}
			<a href="/dashboard" class="text-lg font-semibold text-accent no-underline" data-testid="nav-brand"
				>garde</a
			>
		{/if}
		<div class="nav-links">
			{#if !mfaBlocked}
				<a
					href="/dashboard"
					class="nav-link"
					class:nav-link-active={path.startsWith('/dashboard')}
					aria-current={path.startsWith('/dashboard') ? 'page' : undefined}
					data-testid="nav-dashboard"
				>Dashboard</a>
				{#if $isSuperuser}
					<a
						href="/superuser"
						class="nav-link"
						class:nav-link-active={path.startsWith('/superuser')}
						aria-current={path.startsWith('/superuser') ? 'page' : undefined}
						data-testid="nav-superuser"
					>Superuser</a>
				{:else if $isAdmin}
					<a
						href="/admin"
						class="nav-link"
						class:nav-link-active={path.startsWith('/admin')}
						aria-current={path.startsWith('/admin') ? 'page' : undefined}
						data-testid="nav-admin"
					>Admin</a>
				{/if}
			{/if}
			<button class="btn-secondary" type="button" data-testid="nav-logout" on:click={handleLogout}>
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
{:else}
	<div
		class="container-base max-w-md mx-auto pt-32 text-center text-muted"
		aria-live="polite"
		data-testid="session-redirect"
	>
		<p>Redirecting to sign in…</p>
	</div>
{/if}
