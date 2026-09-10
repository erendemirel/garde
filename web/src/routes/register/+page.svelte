<script>
	import { onMount, onDestroy } from 'svelte';
	import { register } from '$lib/api';
	import { goto } from '$app/navigation';

	let email = '';
	let password = '';
	let confirmPassword = '';
	let error = '';
	let success = '';
	let loading = false;
	let formReady = false;
	/** @type {ReturnType<typeof setTimeout> | null} */
	let redirectTimer = null;

	onMount(() => {
		formReady = true;
	});

	onDestroy(() => {
		if (redirectTimer) clearTimeout(redirectTimer);
	});

	async function handleRegister() {
		if (!formReady || loading) return;
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
			await register(email, password);
			success = 'Account created! Waiting for admin approval.';
			redirectTimer = setTimeout(() => goto('/'), 3000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Registration failed';
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
		{#if success}
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
				on:submit|preventDefault={handleRegister}
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
				{#if error}
					<p class="error" data-testid="register-error">{error}</p>
				{/if}
				<button
					class="btn-secondary w-full justify-center"
					type="submit"
					data-testid="register-submit"
					disabled={!formReady || loading}
				>
					{loading ? 'Creating...' : formReady ? 'Create Account' : 'Loading...'}
				</button>
			</form>
		{/if}
		<div class="links">
			<a href="/" data-testid="register-login-link">Back to login</a>
		</div>
	</div>
</div>
