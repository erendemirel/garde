<script>
	import { onMount, onDestroy } from 'svelte';
	import { requestOtp, resetPassword, getPublicConfig } from '$lib/api';
	import { goto } from '$app/navigation';
	import CapWidget from '$lib/components/CapWidget.svelte';

	let step = $state('email');
	let email = $state('');
	let otp = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let mfaCode = $state('');
	let error = $state('');
	let success = $state('');
	let loading = $state(false);
	let formReady = $state(false);
	let selfService = $state(true);
	let capToken = $state('');
	let capActive = $state(false);
	let capReady = $state(false);
	/** @type {ReturnType<typeof setTimeout> | null} */
	let redirectTimer = $state(null);

	onMount(async () => {
		try {
			const cfg = await getPublicConfig();
			selfService = cfg.public_self_service;
		} catch {
			selfService = true;
		}
		formReady = true;
	});

	onDestroy(() => {
		if (redirectTimer) clearTimeout(redirectTimer);
	});

	async function handleRequestOtp() {
		if (!formReady || loading) return;
		if (capActive && !capToken) {
			error = 'Complete the captcha first';
			return;
		}
		error = '';
		loading = true;
		try {
			await requestOtp(email, capToken || undefined);
			step = 'reset';
			success = 'If the email exists, an OTP has been sent';
			capToken = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to send OTP';
			capToken = '';
		}
		loading = false;
	}

	async function handleReset() {
		if (!formReady || loading) return;
		if (capActive && !capToken) {
			error = 'Complete the captcha first';
			return;
		}
		error = '';
		if (newPassword !== confirmPassword) {
			error = 'Passwords do not match';
			return;
		}
		loading = true;
		try {
			await resetPassword(email, otp, newPassword, mfaCode || undefined, capToken || undefined);
			success = 'Password reset successful.';
			redirectTimer = setTimeout(() => goto('/'), 3000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Password reset failed';
			capToken = '';
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

		{#if formReady && !selfService}
			<p class="text-sm text-muted" data-testid="forgot-disabled">
				Password reset is disabled on this deployment. Contact an administrator.
			</p>
		{:else if step === 'email'}
			<form
				class="space-y-4"
				data-testid="forgot-email-form"
				data-ready={formReady ? 'true' : 'false'}
				aria-busy={!formReady}
				method="post"
				action="#"
				onsubmit={(e) => {
					e.preventDefault();
					void handleRequestOtp();
				}}
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
				<CapWidget bind:token={capToken} bind:active={capActive} bind:ready={capReady} />
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
					disabled={!formReady || !capReady || loading || (capActive && !capToken)}
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
				onsubmit={(e) => {
					e.preventDefault();
					void handleReset();
				}}
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
				<CapWidget bind:token={capToken} bind:active={capActive} bind:ready={capReady} />
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
					disabled={!formReady || !capReady || loading || (capActive && !capToken)}
				>
					{loading ? 'Resetting...' : 'Reset Password'}
				</button>
				<button
					type="button"
					class="btn-secondary w-full justify-center"
					data-testid="forgot-back-to-email"
					onclick={() => {
						step = 'email';
						error = '';
						success = '';
						capToken = '';
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
