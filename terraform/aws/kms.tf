# Customer-managed key that Vault uses for auto-unseal (seal "awskms").
# Recovery keys from `vault operator init` still matter for break-glass
# (generate-root, rekey); day-to-day reboots no longer need Shamir unseal.

resource "aws_kms_key" "vault" {
  description             = "${var.name} Vault auto-unseal"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name    = "${var.name}-vault"
    Project = "garde"
  }
}

resource "aws_kms_alias" "vault" {
  name          = "alias/${var.name}-vault"
  target_key_id = aws_kms_key.vault.key_id
}
