<script>
	import { onMount } from 'svelte';
	import { login } from '$lib/api';
	import { goto } from '$app/navigation';

	let email = '';
	let password = '';
	let mfaCode = '';
	let error = '';
	let needsMfa = false;
	let loading = false;
	/** True after mount — gates interactivity until Svelte handlers are wired. */
	let formReady = false;
	let emailInput;
	let passwordInput;

	onMount(() => {
		formReady = true;
	});

	async function handleLogin() {
		if (!formReady || loading) return;
		error = '';
		if (!emailInput?.checkValidity() || !passwordInput?.checkValidity()) {
			emailInput?.reportValidity();
			passwordInput?.reportValidity();
			return;
		}
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

	function onLoginKeydown(e) {
		if (!formReady || loading) return;
		if (e.key === 'Enter') {
			e.preventDefault();
			void handleLogin();
		}
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
			data-ready={formReady ? 'true' : 'false'}
			aria-busy={!formReady}
			on:keydown={onLoginKeydown}
		>
			<label class="flex flex-col gap-2 text-sm font-semibold text-muted">
				Email
				<input
					class="input"
					type="email"
					data-testid="login-email"
					bind:this={emailInput}
					bind:value={email}
					required
					autocomplete="email"
					disabled={!formReady}
				/>
			</label>
			<label class="flex flex-col gap-2 text-sm font-semibold text-muted">
				Password
				<input
					class="input"
					type="password"
					data-testid="login-password"
					bind:this={passwordInput}
					bind:value={password}
					required
					autocomplete="current-password"
					disabled={!formReady}
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
						disabled={!formReady}
					/>
				</label>
			{/if}
			{#if error}
				<p class="error font-semibold" data-testid="login-error">{error}</p>
			{/if}
			<button
				class="btn-secondary w-full justify-center font-bold"
				type="button"
				data-testid="login-submit"
				disabled={!formReady || loading}
				on:click={handleLogin}
			>
				{loading ? 'Signing in...' : formReady ? 'Sign In' : 'Loading...'}
			</button>
		</form>
		<div class="links font-semibold">
			<a href="/register" data-testid="login-register-link">Create account</a>
			<span class="text-muted">·</span>
			<a href="/forgot-password" data-testid="login-forgot-link">Forgot password?</a>
		</div>
	</div>
</div>
