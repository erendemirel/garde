<script>
	import { onMount } from 'svelte';
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
	let formReady = false;

	onMount(() => {
		formReady = true;
	});

	async function handleRequestOtp() {
		if (!formReady || loading) return;
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
		if (!formReady || loading) return;
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

<div class="container-auth" data-testid="forgot-password-page" data-step={step}>
	<div class="card space-y-4 w-full">
		<h1 class="text-xl font-bold text-accent">Reset Password</h1>

		{#if step === 'email'}
			<form
				class="space-y-4"
				data-testid="forgot-email-form"
				data-ready={formReady ? 'true' : 'false'}
				aria-busy={!formReady}
				method="post"
				action="#"
				onsubmit="return false;"
				on:submit|preventDefault={handleRequestOtp}
			>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Email
					<input
						class="input"
						type="email"
						data-testid="forgot-email"
						bind:value={email}
						required
						disabled={!formReady}
					/>
				</label>
				{#if error}
					<p class="error" data-testid="forgot-error">{error}</p>
				{/if}
				{#if success}
					<p class="success" data-testid="forgot-success">{success}</p>
				{/if}
				<button
					class="btn-secondary w-full justify-center"
					type="submit"
					data-testid="forgot-send-otp"
					disabled={!formReady || loading}
				>
					{loading ? 'Sending...' : formReady ? 'Send OTP' : 'Loading...'}
				</button>
			</form>
		{:else}
			<form
				class="space-y-4"
				data-testid="forgot-reset-form"
				data-ready={formReady ? 'true' : 'false'}
				aria-busy={!formReady}
				method="post"
				action="#"
				onsubmit="return false;"
				on:submit|preventDefault={handleReset}
			>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Email
					<input
						class="input"
						type="email"
						data-testid="forgot-email"
						bind:value={email}
						required
						disabled={!formReady}
					/>
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					OTP Code
					<input
						class="input"
						type="text"
						data-testid="forgot-otp"
						bind:value={otp}
						required
						placeholder="8-character code from email"
						disabled={!formReady}
					/>
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					New Password
					<input
						class="input"
						type="password"
						data-testid="forgot-password"
						bind:value={newPassword}
						required
						minlength="8"
						disabled={!formReady}
					/>
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Confirm Password
					<input
						class="input"
						type="password"
						data-testid="forgot-confirm"
						bind:value={confirmPassword}
						required
						disabled={!formReady}
					/>
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					MFA Code (if enabled)
					<input
						class="input"
						type="text"
						data-testid="forgot-mfa"
						bind:value={mfaCode}
						placeholder="Optional"
						disabled={!formReady}
					/>
				</label>
				{#if error}
					<p class="error" data-testid="forgot-error">{error}</p>
				{/if}
				{#if success}
					<p class="success" data-testid="forgot-success">{success}</p>
				{/if}
				<button
					class="btn-secondary w-full justify-center"
					type="submit"
					data-testid="forgot-reset-submit"
					disabled={!formReady || loading}
				>
					{loading ? 'Resetting...' : 'Reset Password'}
				</button>
				<button
					type="button"
					class="btn-secondary w-full justify-center"
					data-testid="forgot-back-to-email"
					on:click={() => {
						step = 'email';
						error = '';
						success = '';
					}}
				>
					Back
				</button>
			</form>
		{/if}

		<div class="links">
			<a href="/" data-testid="forgot-login-link">Back to login</a>
		</div>
	</div>
</div>
