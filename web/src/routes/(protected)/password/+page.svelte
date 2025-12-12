<script>
	import { changePassword, logout } from '$lib/api';
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

	function requestConfirmation() {
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
		error = '';
		loading = true;
		try {
			await changePassword(oldPassword, newPassword, mfaCode || undefined);
			success = 'Password changed! You will be logged out.';
			setTimeout(async () => {
				await logout();
				user.set(null);
				goto('/');
			}, 2000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Password change failed';
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>Change Password | garde</title>
</svelte:head>

<div class="container-medium">
	<div class="card space-y-4">
		<div class="flex items-start justify-between gap-3">
			<h1 class="page-title">Change Password</h1>
			<a href="/dashboard" class="w-full sm:w-auto sm:ml-auto">
				<button class="btn-secondary w-full sm:w-auto"><ArrowLeft size={18} />Back to Dashboard</button>
			</a>
		</div>

		{#if success}
			<p class="success">{success}</p>
		{:else}
			<form class="space-y-4" on:submit|preventDefault={requestConfirmation}>
				<label class="form-label">
					<span>Current Password</span>
					<input class="input" type="password" bind:value={oldPassword} required />
				</label>
				<label class="form-label">
					<span>New Password</span>
					<input class="input" type="password" bind:value={newPassword} required minlength="8" />
				</label>
				<label class="form-label">
					<span>Confirm New Password</span>
					<input class="input" type="password" bind:value={confirmPassword} required />
				</label>
				{#if $user?.mfa_enabled}
					<label class="form-label">
						<span>MFA Code</span>
						<input class="input" type="text" bind:value={mfaCode} placeholder="6-digit code" required />
					</label>
				{/if}
				{#if error}
					<p class="error">{error}</p>
				{/if}
				<div class="form-actions-center">
					<button class="btn-secondary w-full md:w-auto" type="submit" disabled={loading}>
						<KeyRound size={18} />
						{loading ? 'Changing...' : 'Change Password'}
					</button>
				</div>
			</form>
		{/if}
	</div>
</div>

<ConfirmModal 
	bind:open={showConfirmModal}
	title="Confirm Password Change"
	message="Are you sure you want to change your password? You will be logged out after the change."
	confirmText="Change Password"
	on:confirm={handleChange}
/>

