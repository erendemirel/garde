<script>
	import { requestOtp, resetPassword } from '$lib/api';
	import { goto } from '$app/navigation';

	let step = 'email';
	let email = '';
	let otp = '';
	let newPassword = '';
	let confirmPassword = '';
	let mfaCode = '';
	let error = '';
	let success = '';
	let loading = false;

	async function handleRequestOtp() {
		error = '';
		loading = true;
		try {
			await requestOtp(email);
			step = 'reset';
			success = 'If the email exists, an OTP has been sent';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to send OTP';
		}
		loading = false;
	}

	async function handleReset() {
		error = '';
		if (newPassword !== confirmPassword) {
			error = 'Passwords do not match';
			return;
		}
		loading = true;
		try {
			await resetPassword(email, otp, newPassword, mfaCode || undefined);
			success = 'Password reset successful. Waiting for admin approval.';
			setTimeout(() => goto('/'), 3000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Password reset failed';
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>Reset Password | garde</title>
</svelte:head>

<div class="container-auth">
	<div class="card space-y-4 w-full">
		<h1 class="text-xl font-bold text-accent">Reset Password</h1>
		<p class="section-subtitle">We'll guide you through email verification.</p>

		{#if step === 'email'}
			<form class="space-y-4" on:submit|preventDefault={handleRequestOtp}>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Email
					<input class="input" type="email" bind:value={email} required />
				</label>
				{#if error}
					<p class="error">{error}</p>
				{/if}
				{#if success}
					<p class="success">{success}</p>
				{/if}
				<button class="btn-secondary w-full justify-center" type="submit" disabled={loading}>
					{loading ? 'Sending...' : 'Send OTP'}
				</button>
				<button type="button" class="btn-secondary w-full justify-center" on:click={() => (step = 'reset')}>
					I have an OTP
				</button>
			</form>
		{:else}
			<form class="space-y-4" on:submit|preventDefault={handleReset}>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Email
					<input class="input" type="email" bind:value={email} required />
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					OTP Code
					<input class="input" type="text" bind:value={otp} required placeholder="5-letter code from email" />
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					New Password
					<input class="input" type="password" bind:value={newPassword} required minlength="8" />
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Confirm Password
					<input class="input" type="password" bind:value={confirmPassword} required />
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					MFA Code (if enabled)
					<input class="input" type="text" bind:value={mfaCode} placeholder="Optional" />
				</label>
				{#if error}
					<p class="error">{error}</p>
				{/if}
				{#if success}
					<p class="success">{success}</p>
				{/if}
				<button class="btn-secondary w-full justify-center" type="submit" disabled={loading}>
					{loading ? 'Resetting...' : 'Reset Password'}
				</button>
				<button type="button" class="btn-secondary w-full justify-center" on:click={() => (step = 'email')}>
					Back
				</button>
			</form>
		{/if}

		<div class="links">
			<a href="/">Back to login</a>
		</div>
	</div>
</div>

