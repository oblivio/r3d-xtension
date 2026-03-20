# Production KMS Setup for R3D CSFLE
# This creates a Customer Master Key with proper IAM policies, key rotation,
# and CloudWatch logging for compliance.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "environment" {
  description = "Environment name (staging, production)"
  type        = string
  default     = "production"
}

variable "service_role_arn" {
  description = "ARN of the IAM role for R3D proxy service (EC2/ECS/EKS)"
  type        = string
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail logging for KMS API calls"
  type        = bool
  default     = true
}

# ─── KMS Customer Master Key ─────────────────────────────────────────

resource "aws_kms_key" "r3d_csfle" {
  description              = "R3D CSFLE Master Key - ${var.environment}"
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"

  # Enable automatic key rotation (annual)
  enable_key_rotation = true

  # Deletion window (7 days minimum, 30 days recommended for production)
  deletion_window_in_days = 30

  # Key policy - restrict to service IAM role only
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow R3D Service to Use Key"
        Effect = "Allow"
        Principal = {
          AWS = var.service_role_arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs Encryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "r3d-csfle-${var.environment}"
    Environment = var.environment
    Purpose     = "MongoDB CSFLE credential encryption"
    ManagedBy   = "Terraform"
    Compliance  = "SOC2,PCI-DSS"
  }
}

resource "aws_kms_alias" "r3d_csfle" {
  name          = "alias/r3d-csfle-${var.environment}"
  target_key_id = aws_kms_key.r3d_csfle.key_id
}

# ─── CloudWatch Logging ──────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "kms_audit" {
  count             = var.enable_cloudtrail ? 1 : 0
  name              = "/aws/kms/r3d-csfle-${var.environment}"
  retention_in_days = 90  # Adjust per compliance requirements

  kms_key_id = aws_kms_key.r3d_csfle.arn

  tags = {
    Name        = "r3d-kms-audit-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ─── CloudTrail for KMS API Auditing ─────────────────────────────────

resource "aws_cloudtrail" "kms_audit" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "r3d-kms-audit-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::KMS::Key"
      values = [
        "${aws_kms_key.r3d_csfle.arn}"
      ]
    }
  }

  tags = {
    Name        = "r3d-kms-audit-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail[0]]
}

resource "aws_s3_bucket" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = "r3d-kms-audit-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "r3d-kms-audit-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.r3d_csfle.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail[0].arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# ─── Data Sources ────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── Outputs ─────────────────────────────────────────────────────────

output "kms_key_id" {
  description = "KMS Key ID for R3D CSFLE"
  value       = aws_kms_key.r3d_csfle.key_id
}

output "kms_key_arn" {
  description = "KMS Key ARN (use this in AWS_KMS_KEY_ARN env var)"
  value       = aws_kms_key.r3d_csfle.arn
  sensitive   = true
}

output "kms_alias_name" {
  description = "KMS Alias for easy reference"
  value       = aws_kms_alias.r3d_csfle.name
}

output "cloudtrail_bucket" {
  description = "S3 bucket for KMS audit logs"
  value       = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail[0].bucket : null
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for KMS audit"
  value       = var.enable_cloudtrail ? aws_cloudwatch_log_group.kms_audit[0].name : null
}
