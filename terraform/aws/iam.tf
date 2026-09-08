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
