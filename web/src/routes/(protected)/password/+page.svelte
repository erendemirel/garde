<script>
	import { onMount } from 'svelte';
	import { changePassword, invalidateSession, logout } from '$lib/api';
	import { goto } from '$app/navigation';
	import { user } from '$lib/stores';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import { ArrowLeft, KeyRound } from 'lucide-svelte';

	let oldPassword = '';
	let newPassword = '';
	let confirmPassword = '';
	let mfaCode = '';
	let error = '';
	let success = '';
	let loading = false;
	let showConfirmModal = false;
	let formReady = false;

	onMount(() => {
		formReady = true;
	});

	function requestConfirmation() {
		if (!formReady || loading) return;
		error = '';
		if (newPassword !== confirmPassword) {
			error = 'Passwords do not match';
			return;
		}
		if (newPassword.length < 8) {
			error = 'Password must be at least 8 characters';
			return;
		}
		showConfirmModal = true;
	}

	async function handleChange() {
		if (!formReady || loading) return;
		error = '';
		loading = true;
		try {
			await changePassword(oldPassword, newPassword, mfaCode || undefined);
			success = 'Password changed! You will be logged out.';
			invalidateSession();
			try {
				await logout();
			} catch {}
			goto('/');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Password change failed';
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>Change Password | garde</title>
</svelte:head>

<div class="container-medium" data-testid="password-page">
	<div class="card space-y-4">
		<div class="flex items-start justify-between gap-3">
			<h1 class="page-title">Change Password</h1>
			<a
				href="/dashboard"
				class="btn-secondary w-full sm:w-auto sm:ml-auto"
				data-testid="password-back"
				><ArrowLeft size={18} />Back to Dashboard</a
			>
		</div>

		{#if success}
			<p class="success" data-testid="password-success">{success}</p>
		{:else}
			<form
				class="space-y-4"
				data-testid="password-form"
				data-ready={formReady ? 'true' : 'false'}
				aria-busy={!formReady}
				method="post"
				action="#"
				onsubmit="return false;"
				on:submit|preventDefault={requestConfirmation}
			>
				<label class="form-label">
					<span>Current Password</span>
					<input
						class="input"
						type="password"
						data-testid="password-current"
						bind:value={oldPassword}
						required
						disabled={!formReady}
					/>
				</label>
				<label class="form-label">
					<span>New Password</span>
					<input
						class="input"
						type="password"
						data-testid="password-new"
						bind:value={newPassword}
						required
						minlength="8"
						disabled={!formReady}
					/>
				</label>
				<label class="form-label">
					<span>Confirm New Password</span>
					<input
						class="input"
						type="password"
						data-testid="password-confirm"
						bind:value={confirmPassword}
						required
						disabled={!formReady}
					/>
				</label>
				{#if $user?.mfa_enabled}
					<label class="form-label">
						<span>MFA Code</span>
						<input
							class="input"
							type="text"
							data-testid="password-mfa"
							bind:value={mfaCode}
							placeholder="6-digit code"
							required
							disabled={!formReady}
						/>
					</label>
				{/if}
				{#if error}
					<p class="error" data-testid="password-error">{error}</p>
				{/if}
				<div class="form-actions-center">
					<button
						class="btn-secondary w-full md:w-auto"
						type="submit"
						data-testid="password-submit"
						disabled={!formReady || loading}
					>
						<KeyRound size={18} />
						{loading ? 'Changing...' : formReady ? 'Change Password' : 'Loading...'}
					</button>
				</div>
			</form>
		{/if}
	</div>
</div>

<ConfirmModal
	bind:open={showConfirmModal}
	title="Confirm Password Change"
	message="Change your password now? You will be signed out immediately and must sign in with the new password."
	confirmText="Change Password"
	on:confirm={handleChange}
/>
