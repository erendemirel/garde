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

<div class="container-auth" data-testid="login-page">
	<div class="card space-y-4 w-full">
		<h1 class="text-xl font-extrabold text-accent">garde</h1>
		<form
			class="space-y-4"
			data-testid="login-form"
			method="post"
			action="#"
			onsubmit="return false;"
			on:submit|preventDefault={handleLogin}
		>
			<label class="flex flex-col gap-2 text-sm font-semibold text-muted">
				Email
				<input
					class="input"
					type="email"
					data-testid="login-email"
					bind:value={email}
					required
					autocomplete="email"
				/>
			</label>
			<label class="flex flex-col gap-2 text-sm font-semibold text-muted">
				Password
				<input
					class="input"
					type="password"
					data-testid="login-password"
					bind:value={password}
					required
					autocomplete="current-password"
				/>
			</label>
			{#if needsMfa}
				<label class="flex flex-col gap-2 text-sm font-semibold text-muted">
					MFA Code
					<input
						class="input"
						type="text"
						data-testid="login-mfa"
						bind:value={mfaCode}
						placeholder="6-digit code"
						autocomplete="one-time-code"
					/>
				</label>
			{/if}
			{#if error}
				<p class="error font-semibold" data-testid="login-error">{error}</p>
			{/if}
			<button
				class="btn-secondary w-full justify-center font-bold"
				type="submit"
				data-testid="login-submit"
				disabled={loading}
			>
				{loading ? 'Signing in...' : 'Sign In'}
			</button>
		</form>
		<div class="links font-semibold">
			<a href="/register" data-testid="login-register-link">Create account</a>
			<span class="text-muted">·</span>
			<a href="/forgot-password" data-testid="login-forgot-link">Forgot password?</a>
		</div>
	</div>
</div>
