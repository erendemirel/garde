<script>
	import { register } from '$lib/api';
	import { goto } from '$app/navigation';

	let email = '';
	let password = '';
	let confirmPassword = '';
	let error = '';
	let success = '';
	let loading = false;

	async function handleRegister() {
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
			setTimeout(() => goto('/'), 3000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Registration failed';
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>Register | garde</title>
</svelte:head>

<div class="container-auth">
	<div class="card space-y-4 w-full">
		<h1 class="text-xl font-bold text-accent">Create Account</h1>
		<p class="section-subtitle">Start with an email and a strong password.</p>
		{#if success}
			<p class="success">{success}</p>
		{:else}
			<form class="space-y-4" on:submit|preventDefault={handleRegister}>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Email
					<input class="input" type="email" bind:value={email} required autocomplete="email" />
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Password
					<input class="input" type="password" bind:value={password} required minlength="8" autocomplete="new-password" />
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Confirm Password
					<input class="input" type="password" bind:value={confirmPassword} required autocomplete="new-password" />
				</label>
				{#if error}
					<p class="error">{error}</p>
				{/if}
				<button class="btn-secondary w-full justify-center" type="submit" disabled={loading}>
					{loading ? 'Creating...' : 'Create Account'}
				</button>
			</form>
		{/if}
		<div class="links">
			<a href="/">Back to login</a>
		</div>
	</div>
</div>

