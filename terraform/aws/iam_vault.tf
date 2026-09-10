# Instance role for the three EC2 nodes: only enough KMS access for Vault
# awskms auto-unseal. No long-lived access keys on the hosts.

data "aws_iam_policy_document" "vault_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "vault_kms" {
  statement {
    sid = "VaultAutoUnseal"
    # HashiCorp awskms seal: Encrypt + Decrypt + DescribeKey.
    # GenerateDataKey is unused by auto-unseal but harmless if left in.
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.vault.arn]
  }
}

resource "aws_iam_role" "vault" {
  name               = "${var.name}-vault"
  assume_role_policy = data.aws_iam_policy_document.vault_assume.json

  tags = {
    Name    = "${var.name}-vault"
    Project = "garde"
  }
}

resource "aws_iam_role_policy" "vault_kms" {
  name   = "${var.name}-vault-kms"
  role   = aws_iam_role.vault.id
  policy = data.aws_iam_policy_document.vault_kms.json
}

resource "aws_iam_instance_profile" "vault" {
  name = "${var.name}-vault"
  role = aws_iam_role.vault.name
}
