<script>
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { getPublicConfig, verifyEmail, resendVerifyEmail } from '$lib/api';
	import CapWidget from '$lib/components/CapWidget.svelte';

	let email = $state('');
	let token = $state('');
	let error = $state('');
	let success = $state('');
	let loading = $state(false);
	let resending = $state(false);
	let formReady = $state(false);
	let selfService = $state(true);
	let verifyRequired = $state(false);
	let capToken = $state('');
	let capActive = $state(false);
	let capReady = $state(false);

	onMount(async () => {
		const qEmail = $page.url.searchParams.get('email');
		if (qEmail) email = qEmail;
		try {
			const cfg = await getPublicConfig();
			selfService = cfg.public_self_service;
			verifyRequired = cfg.require_email_verification;
		} catch {
			selfService = true;
			verifyRequired = true;
		}
		formReady = true;
	});

	async function handleVerify() {
		if (!formReady || loading || !selfService) return;
		if (capActive && !capToken) {
			error = 'Complete the captcha first';
			return;
		}
		error = '';
		success = '';
		loading = true;
		try {
			await verifyEmail(email, token.trim(), capToken || undefined);
			success =
				'If the email and code are valid, your address is verified. You can sign in once any remaining approval steps finish.';
			setTimeout(() => goto('/'), 3500);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Verification failed';
			capToken = '';
		}
		loading = false;
	}

	async function handleResend() {
		if (!formReady || resending || !selfService || !email) return;
		if (capActive && !capToken) {
			error = 'Complete the captcha first';
			return;
		}
		error = '';
		resending = true;
		try {
			await resendVerifyEmail(email, capToken || undefined);
			success = 'If that address needs verification, a new code has been sent.';
			capToken = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Resend failed';
			capToken = '';
		}
		resending = false;
	}
</script>

<svelte:head>
	<title>Verify email | garde</title>
</svelte:head>

<div class="container-auth" data-testid="verify-email-page">
	<div class="card space-y-4 w-full">
		<h1 class="text-xl font-bold text-accent">Verify email</h1>
		{#if formReady && (!selfService || !verifyRequired)}
			<p class="text-sm text-muted" data-testid="verify-email-disabled">
				{#if !selfService}
					Public self-service is disabled.
				{:else}
					Email verification is not required on this deployment.
				{/if}
			</p>
		{:else}
			<form
				class="space-y-4"
				data-testid="verify-email-form"
				method="post"
				action="#"
				onsubmit={(e) => {
					e.preventDefault();
					void handleVerify();
				}}
			>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Email
					<input
						class="input"
						type="email"
						data-testid="verify-email-input"
						bind:value={email}
						required
						autocomplete="email"
						disabled={!formReady}
					/>
				</label>
				<label class="flex flex-col gap-2 text-sm text-muted">
					Verification code
					<input
						class="input"
						type="text"
						data-testid="verify-email-token"
						bind:value={token}
						required
						minlength="16"
						autocomplete="one-time-code"
						disabled={!formReady}
					/>
				</label>
				<CapWidget bind:token={capToken} bind:active={capActive} bind:ready={capReady} />
				{#if error}
					<p class="error" data-testid="verify-email-error">{error}</p>
				{/if}
				{#if success}
					<p class="success" data-testid="verify-email-success">{success}</p>
				{/if}
				<button
					class="btn-secondary w-full justify-center"
					type="submit"
					data-testid="verify-email-submit"
					disabled={!formReady || !capReady || loading || (capActive && !capToken)}
				>
					{loading ? 'Verifying...' : 'Verify'}
				</button>
				<button
					class="btn-secondary w-full justify-center"
					type="button"
					data-testid="verify-email-resend"
					onclick={() => void handleResend()}
					disabled={!formReady || !capReady || resending || !email || (capActive && !capToken)}
				>
					{resending ? 'Sending...' : 'Resend code'}
				</button>
			</form>
		{/if}
		<div class="links">
			<a href="/" data-testid="verify-email-login-link">Back to login</a>
		</div>
	</div>
</div>
