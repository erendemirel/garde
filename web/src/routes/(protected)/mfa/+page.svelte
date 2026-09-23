<script>
	import { onMount, onDestroy } from 'svelte';
	import { setupMfa, verifyMfa, disableMfa } from '$lib/api';
	import { user } from '$lib/stores';
	import { refreshSession } from '$lib/session';
	import { goto } from '$app/navigation';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import { ArrowLeft, ShieldCheck, ShieldOff, CheckCircle, X } from '@lucide/svelte';

	let step = $state('choice');
	let secret = $state('');
	let qrCodeUrl = $state('');
	let verifyCode = $state('');
	let disableCode = $state('');
	let error = $state('');
	let success = $state('');
	let loading = $state(false);
	let showConfirmModal = $state(false);
	let formReady = $state(false);
	/** @type {ReturnType<typeof setTimeout> | null} */
	let redirectTimer = $state(null);

	let safeQrSrc = $derived(
		typeof qrCodeUrl === 'string' &&
			(qrCodeUrl.startsWith('data:image/') || qrCodeUrl.startsWith('https://'))
			? qrCodeUrl
			: ''
	);

	let mustSetup = $derived(!!$user?.mfa_enforced && !$user?.mfa_enabled);
	let canDisable = $derived(!!$user?.mfa_enabled && !$user?.mfa_enforced);

	onMount(() => {
		formReady = true;
	});

	onDestroy(() => {
		if (redirectTimer) clearTimeout(redirectTimer);
	});

	function clearSetupState() {
		secret = '';
		qrCodeUrl = '';
		verifyCode = '';
	}

	function goToChoice() {
		clearSetupState();
		disableCode = '';
		error = '';
		step = 'choice';
	}

	async function handleSetup() {
		if (!formReady || loading) return;
		error = '';
		loading = true;
		try {
			const res = await setupMfa();
			secret = res.secret;
			qrCodeUrl = res.qr_code_url;
			verifyCode = '';
			step = 'verify';
		} catch (e) {
			error = e instanceof Error ? e.message : 'MFA setup failed';
		}
		loading = false;
	}

	async function handleVerify() {
		if (!formReady || loading) return;
		error = '';
		loading = true;
		try {
			await verifyMfa(verifyCode);
			clearSetupState();
			success = 'MFA enabled successfully!';
			await refreshSession();
			redirectTimer = setTimeout(() => goto('/dashboard'), 2000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Verification failed';
		}
		loading = false;
	}

	function requestDisableConfirmation() {
		showConfirmModal = true;
	}

	async function handleDisable() {
		if (!formReady || loading) return;
		error = '';
		loading = true;
		try {
			await disableMfa(disableCode);
			disableCode = '';
			success = 'MFA disabled successfully!';
			await refreshSession();
			redirectTimer = setTimeout(() => goto('/dashboard'), 2000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to disable MFA';
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>MFA | garde</title>
</svelte:head>

<div class="container-wide" data-testid="mfa-page" data-step={step}>
	{#if !mustSetup}
		<div class="mb-4">
			<a
				href="/dashboard"
				class="btn-secondary inline-flex items-center gap-2"
				data-testid="mfa-back"
			>
				<ArrowLeft size={16} /> Dashboard
			</a>
		</div>
	{/if}

	<div class="card space-y-4">
		<div class="flex flex-wrap items-start justify-between gap-3">
			<div>
				<h1 class="page-title">Multi-Factor Authentication</h1>
				<p class="section-subtitle">
					Add an authenticator app as a second step when you sign in.
				</p>
			</div>
			{#if !success && step === 'choice'}
				{#if !$user?.mfa_enabled}
					<button
						class="btn-primary"
						type="button"
						data-testid="mfa-setup"
						onclick={handleSetup}
						disabled={!formReady || loading}
					>
						<ShieldCheck size={16} class="inline mr-1" />
						{loading ? 'Setting up...' : formReady ? 'Setup MFA' : 'Loading...'}
					</button>
				{:else if canDisable}
					<button
						class="btn-danger"
						type="button"
						data-testid="mfa-disable-start"
						onclick={() => {
							disableCode = '';
							error = '';
							step = 'disable';
						}}
					>
						<ShieldOff size={16} class="inline mr-1" />Disable MFA
					</button>
				{/if}
			{/if}
		</div>

		{#if success}
			<p class="success" data-testid="mfa-success">{success}</p>
		{:else if step === 'choice'}
			{#if $user?.mfa_enabled}
				<p class="text-sm text-text" data-testid="mfa-status">
					MFA is currently <strong>enabled</strong>.
				</p>
				{#if $user?.mfa_enforced}
					<p class="error" data-testid="mfa-error">MFA is enforced and cannot be disabled.</p>
				{:else}
					<p class="text-sm text-muted">
						You can disable MFA with a code from your authenticator app.
					</p>
				{/if}
			{:else if $user?.mfa_enforced}
				<p class="text-sm text-warning font-semibold">MFA has been enforced for your account.</p>
				<p class="text-sm text-muted">
					You must set up MFA before you can continue using the application.
				</p>
				<p class="text-sm text-text" data-testid="mfa-status">
					MFA is currently <strong>disabled</strong>.
				</p>
			{:else}
				<p class="text-sm text-text" data-testid="mfa-status">
					MFA is currently <strong>disabled</strong>.
				</p>
				<p class="text-sm text-muted">
					Use Setup MFA to scan a QR code and verify a one-time code from your authenticator app.
				</p>
			{/if}
		{:else if step === 'verify'}
			<p class="text-sm text-text">Scan this QR code with your authenticator app:</p>
			<div class="qr-code" data-testid="mfa-qr">
				{#if safeQrSrc}
					<img src={safeQrSrc} alt="MFA QR Code" width="200" height="200" />
				{:else}
					<p class="text-sm text-muted">QR code unavailable. Use the secret below.</p>
				{/if}
			</div>
			<p class="text-sm text-muted">Or enter this secret manually:</p>
			<p class="secret-key" data-testid="mfa-secret">{secret}</p>
			<form
				class="space-y-4"
				data-testid="mfa-verify-form"
				data-ready={formReady ? 'true' : 'false'}
				aria-busy={!formReady}
				method="post"
				action="#"
				onsubmit={(e) => {
					e.preventDefault();
					handleVerify();
				}}
			>
				<label class="form-label">
					<span>Enter code from app</span>
					<input
						class="input"
						type="text"
						data-testid="mfa-code"
						bind:value={verifyCode}
						placeholder="6-digit code"
						required
						autocomplete="one-time-code"
						disabled={!formReady}
					/>
				</label>
				{#if error}
					<p class="error" data-testid="mfa-error">{error}</p>
				{/if}
				<div class="form-actions">
					<button
						type="button"
						class="btn-secondary"
						data-testid="mfa-verify-cancel"
						onclick={goToChoice}
						disabled={loading}
					>
						<X size={18} />Cancel
					</button>
					<button
						class="btn-primary"
						type="submit"
						data-testid="mfa-verify-submit"
						disabled={!formReady || loading}
					>
						<CheckCircle size={18} />
						{loading ? 'Verifying...' : formReady ? 'Verify & Enable' : 'Loading...'}
					</button>
				</div>
			</form>
		{:else if step === 'disable'}
			<p class="text-sm text-text">Enter your MFA code to disable:</p>
			<form
				class="space-y-4"
				data-testid="mfa-disable-form"
				data-ready={formReady ? 'true' : 'false'}
				aria-busy={!formReady}
				method="post"
				action="#"
				onsubmit={(e) => {
					e.preventDefault();
					requestDisableConfirmation();
				}}
			>
				<label class="form-label">
					<span>MFA Code</span>
					<input
						class="input"
						type="text"
						data-testid="mfa-code"
						bind:value={disableCode}
						placeholder="6-digit code"
						required
						autocomplete="one-time-code"
						disabled={!formReady}
					/>
				</label>
				{#if error}
					<p class="error" data-testid="mfa-error">{error}</p>
				{/if}
				<div class="form-actions">
					<button
						type="button"
						class="btn-secondary"
						data-testid="mfa-disable-cancel"
						onclick={goToChoice}
					>
						<X size={18} />Cancel
					</button>
					<button
						class="btn-danger"
						type="submit"
						data-testid="mfa-disable-submit"
						disabled={!formReady || loading}
					>
						<ShieldOff size={18} />
						{loading ? 'Disabling...' : formReady ? 'Disable MFA' : 'Loading...'}
					</button>
				</div>
			</form>
		{/if}
	</div>
</div>

<ConfirmModal
	bind:open={showConfirmModal}
	title="Disable MFA"
	message="Disable MFA now? Your next sign-in will only require email and password until you set MFA up again."
	confirmText="Disable MFA"
	confirmClass="btn-danger"
	onConfirm={handleDisable}
/>
