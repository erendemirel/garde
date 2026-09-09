# Where CI stages images for the hosts to fetch.
#
# The bucket is private and stays private: hosts read from it through presigned
# URLs that CI generates and that expire in fifteen minutes, so nothing here
# ever grants an instance a standing credential.

resource "aws_s3_bucket" "images" {
  bucket        = var.image_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "images" {
  bucket = aws_s3_bucket.images.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "images" {
  bucket = aws_s3_bucket.images.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# A staged image is consumed within minutes of being uploaded and is worthless
# afterwards, so nothing needs to accumulate.
resource "aws_s3_bucket_lifecycle_configuration" "images" {
  bucket = aws_s3_bucket.images.id

  rule {
    id     = "expire-staged-images"
    status = "Enabled"

    filter {
      prefix = "garde-images/"
    }

    expiration {
      days = var.image_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}
