<script>
	import { setupMfa, verifyMfa, disableMfa, getMe } from '$lib/api';
	import { user } from '$lib/stores';
	import { goto } from '$app/navigation';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import { ArrowLeft, ShieldCheck, ShieldOff, CheckCircle, X } from 'lucide-svelte';

	let step = 'choice';
	let secret = '';
	let qrCodeUrl = '';
	let code = '';
	let error = '';
	let success = '';
	let loading = false;
	let showConfirmModal = false;

	async function handleSetup() {
		error = '';
		loading = true;
		try {
			const res = await setupMfa();
			secret = res.secret;
			qrCodeUrl = res.qr_code_url;
			step = 'verify';
		} catch (e) {
			error = e instanceof Error ? e.message : 'MFA setup failed';
		}
		loading = false;
	}

	async function handleVerify() {
		error = '';
		loading = true;
		try {
			await verifyMfa(code);
			success = 'MFA enabled successfully!';
			const me = await getMe();
			user.set(me);
			setTimeout(() => goto('/dashboard'), 2000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Verification failed';
		}
		loading = false;
	}

	function requestDisableConfirmation() {
		showConfirmModal = true;
	}

	async function handleDisable() {
		error = '';
		loading = true;
		try {
			await disableMfa(code);
			success = 'MFA disabled successfully!';
			const me = await getMe();
			user.set(me);
			setTimeout(() => goto('/dashboard'), 2000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to disable MFA';
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>MFA | garde</title>
</svelte:head>

<div class="container-medium">
	<div class="card space-y-4">
		<div class="flex items-start justify-between gap-3">
			<h1 class="page-title">Multi-Factor Authentication</h1>
			<a href="/dashboard" class="w-full sm:w-auto sm:ml-auto">
				<button class="btn-secondary w-full sm:w-auto"><ArrowLeft size={18} />Back to Dashboard</button>
			</a>
		</div>

		{#if success}
			<p class="success">{success}</p>
		{:else if step === 'choice'}
			{#if $user?.mfa_enabled}
				<p class="text-sm text-text mb-4">MFA is currently <strong>enabled</strong>.</p>
				{#if $user?.mfa_enforced}
					<p class="error">MFA is enforced and cannot be disabled.</p>
				{:else}
					<button class="btn-danger" on:click={() => (step = 'disable')}><ShieldOff size={18} />Disable MFA</button>
				{/if}
			{:else}
				{#if $user?.mfa_enforced}
					<p class="text-sm text-warning mb-2 font-semibold">MFA has been enforced for your account.</p>
					<p class="text-sm text-muted mb-4">You must set up MFA before you can continue using the application.</p>
				{:else}
					<p class="text-sm text-text mb-4">MFA is currently <strong>disabled</strong>.</p>
				{/if}
				<div class="flex justify-center">
					<button class="btn-secondary" on:click={handleSetup} disabled={loading}>
						<ShieldCheck size={18} />
						{loading ? 'Setting up...' : 'Setup MFA'}
					</button>
				</div>
			{/if}
		{:else if step === 'verify'}
			<p class="text-sm text-text mb-3">Scan this QR code with your authenticator app:</p>
			<div class="qr-code">
				<img src={qrCodeUrl} alt="MFA QR Code" width="200" height="200" />
			</div>
			<p class="text-sm text-muted my-3">Or enter this secret manually:</p>
			<p class="secret-key">{secret}</p>
			<form class="space-y-4 mt-4" on:submit|preventDefault={handleVerify}>
				<label class="form-label">
					<span>Enter code from app</span>
					<input class="input" type="text" bind:value={code} placeholder="6-digit code" required />
				</label>
				{#if error}
					<p class="error">{error}</p>
				{/if}
				<button class="btn-secondary" type="submit" disabled={loading}>
					<CheckCircle size={18} />
					{loading ? 'Verifying...' : 'Verify & Enable'}
				</button>
			</form>
		{:else if step === 'disable'}
			<p class="text-sm text-text mb-3">Enter your MFA code to disable:</p>
			<form class="space-y-4" on:submit|preventDefault={requestDisableConfirmation}>
				<label class="form-label">
					<span>MFA Code</span>
					<input class="input" type="text" bind:value={code} placeholder="6-digit code" required />
				</label>
				{#if error}
					<p class="error">{error}</p>
				{/if}
				<div class="flex flex-wrap gap-3">
					<button class="btn-danger" type="submit" disabled={loading}>
						<ShieldOff size={18} />
						{loading ? 'Disabling...' : 'Disable MFA'}
					</button>
					<button type="button" class="btn-secondary" on:click={() => (step = 'choice')}><X size={18} />Cancel</button>
				</div>
			</form>
		{/if}

	</div>
</div>

<ConfirmModal 
	bind:open={showConfirmModal}
	title="Disable MFA"
	message="Are you sure you want to disable MFA? This will reduce your account security."
	confirmText="Disable MFA"
	confirmClass="btn-danger"
	on:confirm={handleDisable}
/>

