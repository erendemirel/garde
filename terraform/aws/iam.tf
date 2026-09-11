# The identity CI acts as. Its permissions are the whole list of things the
# driver does and nothing else: look at addresses and instances, move the one
# address, power-cycle a host to fence it, open a tunnel, and stage an image.
#
# Notably absent: RunInstances, TerminateInstances, and any write to the bucket
# beyond the staging prefix. A leaked key should be able to disrupt this cluster
# and not to build anything new with your account.

data "aws_iam_policy_document" "ci" {
  statement {
    sid = "Read"
    actions = [
      "ec2:DescribeAddresses",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceConnectEndpoints",
    ]
    # The describe calls do not accept resource-level conditions.
    resources = ["*"]
  }

  statement {
    sid = "MoveTheFailoverAddress"
    actions = [
      "ec2:AssociateAddress",
      "ec2:DisassociateAddress",
    ]
    resources = ["*"]
  }

  # Same verb, different mechanism: in managed_lb mode "route traffic to this
  # node" is a target registration rather than an address move. Granted only in
  # that mode, so a floating-IP deployment's key cannot touch load balancers.
  dynamic "statement" {
    for_each = local.managed_lb ? [1] : []

    content {
      sid = "MoveTheLoadBalancerTarget"
      actions = [
        "elasticloadbalancing:RegisterTargets",
        "elasticloadbalancing:DeregisterTargets",
        "elasticloadbalancing:DescribeTargetHealth",
      ]
      resources = ["*"]
    }
  }

  statement {
    sid = "Fence"
    actions = [
      "ec2:StartInstances",
      "ec2:StopInstances",
      "ec2:RebootInstances",
    ]
    resources = ["*"]

    # Scoped to this cluster's hosts, so the key cannot stop unrelated
    # instances in the same account.
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/Project"
      values   = ["garde"]
    }
  }

  statement {
    sid       = "OpenTheTunnel"
    actions   = ["ec2-instance-connect:OpenTunnel"]
    resources = ["*"]
  }

  statement {
    sid = "StageImages"
    # GetObject is needed even though the host does the fetching: a presigned
    # URL inherits the permissions of whoever signed it.
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.images.arn}/garde-images/*"]
  }
}

resource "aws_iam_user" "ci" {
  name = "${var.name}-ci"
}

resource "aws_iam_user_policy" "ci" {
  name   = "${var.name}-ci"
  user   = aws_iam_user.ci.name
  policy = data.aws_iam_policy_document.ci.json
}

# The secret lands in Terraform state, so treat the state file as a secret or
# move to a remote backend with encryption before this is more than a test.
resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}

# --- ACME / Route53 --------------------------------------------------------
# Separate from the compute CI user on purpose: Caddy on the hosts needs
# ChangeResourceRecordSets for DNS-01, and that must not ride on the same key
# that can fence instances and move the Elastic IP.
#
# Not created in managed_lb mode: ACM owns the certificate there, nothing on a
# host answers a challenge, and the best credential is the one that does not
# exist.

data "aws_iam_policy_document" "acme" {
  count = local.manage_acme ? 1 : 0

  statement {
    sid = "ChangeChallengeRecords"
    actions = [
      "route53:ChangeResourceRecordSets",
      "route53:ListResourceRecordSets",
      "route53:GetChange",
    ]
    resources = [
      local.hosted_zone_arn,
      "arn:aws:route53:::change/*",
    ]
  }

  statement {
    sid       = "FindTheZone"
    actions   = ["route53:ListHostedZones", "route53:ListHostedZonesByName"]
    resources = ["*"]
  }
}

resource "aws_iam_user" "acme" {
  count = local.manage_acme ? 1 : 0
  name  = "${var.name}-acme"
}

resource "aws_iam_user_policy" "acme" {
  count  = local.manage_acme ? 1 : 0
  name   = "${var.name}-acme"
  user   = aws_iam_user.acme[0].name
  policy = data.aws_iam_policy_document.acme[0].json
}

resource "aws_iam_access_key" "acme" {
  count = local.manage_acme ? 1 : 0
  user  = aws_iam_user.acme[0].name
}
