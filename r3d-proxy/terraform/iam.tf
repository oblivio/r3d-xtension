# IAM Role and Policies for R3D Proxy Service
# Demonstrates least-privilege access for EC2/ECS/EKS deployments

# ─── EC2 Instance Profile ────────────────────────────────────────────

resource "aws_iam_role" "r3d_ec2" {
  name               = "r3d-proxy-ec2-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name        = "r3d-proxy-ec2-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_instance_profile" "r3d_ec2" {
  name = "r3d-proxy-ec2-${var.environment}"
  role = aws_iam_role.r3d_ec2.name
}

# ─── ECS Task Role ───────────────────────────────────────────────────

resource "aws_iam_role" "r3d_ecs_task" {
  name               = "r3d-proxy-ecs-task-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name        = "r3d-proxy-ecs-task-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ─── EKS Service Account (IRSA) ──────────────────────────────────────

resource "aws_iam_role" "r3d_eks_irsa" {
  name               = "r3d-proxy-eks-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = var.eks_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(var.eks_oidc_provider_arn, "/^(.*provider/)/", "")}:sub" = "system:serviceaccount:${var.eks_namespace}:r3d-proxy"
          "${replace(var.eks_oidc_provider_arn, "/^(.*provider/)/", "")}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = {
    Name        = "r3d-proxy-eks-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ─── KMS Policy (Least Privilege) ────────────────────────────────────

resource "aws_iam_policy" "kms_csfle" {
  name        = "r3d-kms-csfle-${var.environment}"
  description = "KMS permissions for R3D CSFLE encryption (least privilege)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowKMSForCSFLE"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.r3d_csfle.arn
      }
    ]
  })

  tags = {
    Name        = "r3d-kms-csfle-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ─── CloudWatch Logs Policy ──────────────────────────────────────────

resource "aws_iam_policy" "cloudwatch_logs" {
  name        = "r3d-cloudwatch-logs-${var.environment}"
  description = "CloudWatch Logs permissions for R3D proxy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/r3d/*"
      }
    ]
  })

  tags = {
    Name        = "r3d-cloudwatch-logs-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ─── Attach Policies to Roles ────────────────────────────────────────

resource "aws_iam_role_policy_attachment" "ec2_kms" {
  role       = aws_iam_role.r3d_ec2.name
  policy_arn = aws_iam_policy.kms_csfle.arn
}

resource "aws_iam_role_policy_attachment" "ec2_logs" {
  role       = aws_iam_role.r3d_ec2.name
  policy_arn = aws_iam_policy.cloudwatch_logs.arn
}

resource "aws_iam_role_policy_attachment" "ecs_kms" {
  role       = aws_iam_role.r3d_ecs_task.name
  policy_arn = aws_iam_policy.kms_csfle.arn
}

resource "aws_iam_role_policy_attachment" "ecs_logs" {
  role       = aws_iam_role.r3d_ecs_task.name
  policy_arn = aws_iam_policy.cloudwatch_logs.arn
}

resource "aws_iam_role_policy_attachment" "eks_kms" {
  role       = aws_iam_role.r3d_eks_irsa.name
  policy_arn = aws_iam_policy.kms_csfle.arn
}

resource "aws_iam_role_policy_attachment" "eks_logs" {
  role       = aws_iam_role.r3d_eks_irsa.name
  policy_arn = aws_iam_policy.cloudwatch_logs.arn
}

# ─── Variables ───────────────────────────────────────────────────────

variable "eks_oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider (for IRSA)"
  type        = string
  default     = ""
}

variable "eks_namespace" {
  description = "Kubernetes namespace for R3D proxy (for IRSA)"
  type        = string
  default     = "r3d"
}

# ─── Outputs ─────────────────────────────────────────────────────────

output "ec2_role_arn" {
  description = "IAM role ARN for EC2 deployments"
  value       = aws_iam_role.r3d_ec2.arn
}

output "ec2_instance_profile_name" {
  description = "Instance profile name for EC2 launch config"
  value       = aws_iam_instance_profile.r3d_ec2.name
}

output "ecs_task_role_arn" {
  description = "IAM role ARN for ECS task definition"
  value       = aws_iam_role.r3d_ecs_task.arn
}

output "eks_service_account_role_arn" {
  description = "IAM role ARN for EKS service account (IRSA)"
  value       = aws_iam_role.r3d_eks_irsa.arn
}
