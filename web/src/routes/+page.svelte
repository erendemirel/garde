<script>
	import { login } from '$lib/api';
	import { goto } from '$app/navigation';

	let email = '';
	let password = '';
	let mfaCode = '';
	let error = '';
	let needsMfa = false;
	let loading = false;

	async function handleLogin() {
		error = '';
		loading = true;
		try {
			await login(email, password, mfaCode || undefined);
			goto('/dashboard');
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'Login failed';
			if (msg.toLowerCase().includes('mfa')) {
				needsMfa = true;
				error = 'Enter your MFA code';
			} else {
				error = msg;
			}
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>Login | garde</title>
</svelte:head>

<div class="container-auth">
	<div class="card space-y-4 w-full">
		<h1 class="text-xl font-bold text-accent">garde</h1>
		<form class="space-y-4" on:submit|preventDefault={handleLogin}>
			<label class="flex flex-col gap-2 text-sm text-muted">
				Email
				<input class="input" type="email" bind:value={email} required autocomplete="email" />
			</label>
			<label class="flex flex-col gap-2 text-sm text-muted">
				Password
				<input class="input" type="password" bind:value={password} required autocomplete="current-password" />
			</label>
			{#if needsMfa}
				<label class="flex flex-col gap-2 text-sm text-muted">
					MFA Code
					<input class="input" type="text" bind:value={mfaCode} placeholder="6-digit code" autocomplete="one-time-code" />
				</label>
			{/if}
			{#if error}
				<p class="error">{error}</p>
			{/if}
			<button class="btn-secondary w-full justify-center" type="submit" disabled={loading}>
				{loading ? 'Signing in...' : 'Sign In'}
			</button>
		</form>
		<div class="links">
			<a href="/register">Create account</a>
			<span class="text-muted">·</span>
			<a href="/forgot-password">Forgot password?</a>
		</div>
	</div>
</div>

