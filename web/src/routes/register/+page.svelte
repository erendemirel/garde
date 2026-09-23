<script>
	import { onMount, onDestroy } from 'svelte';
	import { register, getPublicConfig } from '$lib/api';
	import { goto } from '$app/navigation';
	import CapWidget from '$lib/components/CapWidget.svelte';

	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let error = $state('');
	let success = $state('');
	let loading = $state(false);
	let formReady = $state(false);
	let selfService = $state(true);
	let emailVerify = $state(false);
	let configLoaded = $state(false);
	let capToken = $state('');
	let capActive = $state(false);
	let capReady = $state(false);
	/** @type {ReturnType<typeof setTimeout> | null} */
	let redirectTimer = $state(null);

	onMount(async () => {
		try {
			const cfg = await getPublicConfig();
			selfService = cfg.public_self_service;
			emailVerify = cfg.require_email_verification;
		} catch {
			selfService = true;
			emailVerify = false;
		}
		configLoaded = true;
		formReady = true;
	});

	onDestroy(() => {
		if (redirectTimer) clearTimeout(redirectTimer);
	});

	/** @param {string | undefined} next */
	function successMessage(next) {
		if (next === 'verify_email') {
			return 'Account created! Check your email for a verification code.';
		}
		if (next === 'ready') {
			return 'Account created! You can sign in now.';
		}
		return 'Account created! Waiting for admin approval.';
	}

	async function handleRegister() {
		if (!formReady || loading || !selfService) return;
		if (capActive && !capToken) {
			error = 'Complete the captcha first';
			return;
		}
		error = '';
		if (password !== confirmPassword) {
			error = 'Passwords do not match';
			return;
		}
		if (password.length < 8) {
			error = 'Password must be at least 8 characters';
			return;
		}
		loading = true;
		try {
			const resp = await register(email, password, capToken || undefined);
			success = successMessage(resp.next);
			const dest = resp.next === 'verify_email' ? `/verify-email?email=${encodeURIComponent(email)}` : '/';
			redirectTimer = setTimeout(() => goto(dest), 3000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Registration failed';
			capToken = '';
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>Register | garde</title>
</svelte:head>

<div class="container-auth" data-testid="register-page">
	<div class="card space-y-4 w-full">
		<h1 class="text-xl font-bold text-accent">Create Account</h1>
		{#if configLoaded && !selfService}
			<p class="text-sm text-muted" data-testid="register-disabled">
				Public registration is disabled. Contact an administrator for an account.
			</p>
		{:else if success}
			<div data-testid="register-success-panel">
				<p class="success" data-testid="register-success">{success}</p>
			</div>
		{:else}
			<form
				class="space-y-4"
				data-testid="register-form"
				data-ready={formReady ? 'true' : 'false'}
				aria-busy={!formReady}
				method="post"
				action="#"
				onsubmit={(e) => {
					e.preventDefault();
					void handleRegister();
				}}
			>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Email
					<input
						class="input"
						type="email"
						data-testid="register-email"
						bind:value={email}
						required
						autocomplete="email"
						disabled={!formReady}
					/>
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Password
					<input
						class="input"
						type="password"
						data-testid="register-password"
						bind:value={password}
						required
						minlength="8"
						autocomplete="new-password"
						disabled={!formReady}
					/>
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Confirm Password
					<input
						class="input"
						type="password"
						data-testid="register-confirm"
						bind:value={confirmPassword}
						required
						autocomplete="new-password"
						disabled={!formReady}
					/>
				</label>
				<CapWidget bind:token={capToken} bind:active={capActive} bind:ready={capReady} />
				{#if error}
					<p class="error" data-testid="register-error">{error}</p>
				{/if}
				<button
					class="btn-secondary w-full justify-center"
					type="submit"
					data-testid="register-submit"
					disabled={!formReady || !capReady || loading || (capActive && !capToken)}
				>
					{loading ? 'Creating...' : formReady ? 'Create Account' : 'Loading...'}
				</button>
			</form>
		{/if}
		<div class="links">
			<a href="/" data-testid="register-login-link">Back to login</a>
			{#if selfService && emailVerify}
				<span class="text-muted">·</span>
				<a href="/verify-email" data-testid="register-verify-link">Verify email</a>
			{/if}
		</div>
	</div>
</div>
