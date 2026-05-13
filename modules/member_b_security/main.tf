###############################################################################
# MEMBER B — The Security Warden
# IAM Roles, Policies, and KMS Encryption
#
# DESIGN PRINCIPLE:
#   - Each subnet's instances get a dedicated IAM role with least privilege.
#   - Lab role CANNOT access the raw-data S3 bucket (Vault).
#   - KMS key encrypts data at rest so compromised servers see ciphertext.
###############################################################################

variable "project_name"    { type = string }
variable "vault_subnet_id" { type = string }
variable "lab_subnet_id"   { type = string }

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── KMS Key (Encryption at Rest) ──────────────────────────────────────────

resource "aws_kms_key" "data_key" {
  description             = "Encrypts patient data at rest in the Medical Research City"
  deletion_window_in_days = 14
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccountFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowVaultAndRefineryEncryptDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.vault_role.arn,
            aws_iam_role.refinery_role.arn
          ]
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
        Sid    = "LabCanOnlyDecryptAnonymized"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lab_role.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:data_class" = "anonymized"
          }
        }
      }
    ]
  })

  tags = { Name = "${var.project_name}-data-key" }
}

resource "aws_kms_alias" "data_key_alias" {
  name          = "alias/${var.project_name}-data-key"
  target_key_id = aws_kms_key.data_key.key_id
}

# ─── S3 Buckets (Data at Rest) ─────────────────────────────────────────────

resource "aws_s3_bucket" "raw_data" {
  bucket_prefix = "${var.project_name}-vault-raw-"
  force_destroy = true
  tags          = { Name = "${var.project_name}-vault-raw-data" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw_data_enc" {
  bucket = aws_s3_bucket.raw_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket" "anonymized_data" {
  bucket_prefix = "${var.project_name}-lab-anon-"
  force_destroy = true
  tags          = { Name = "${var.project_name}-lab-anonymized-data" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "anon_data_enc" {
  bucket = aws_s3_bucket.anonymized_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_key.arn
    }
    bucket_key_enabled = true
  }
}

# ─── IAM Roles ─────────────────────────────────────────────────────────────

# Common assume-role policy for EC2
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# --- Vault Role: read/write raw data, write anonymized ---
resource "aws_iam_role" "vault_role" {
  name               = "${var.project_name}-vault-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = { Name = "${var.project_name}-vault-role" }
}

resource "aws_iam_role_policy" "vault_policy" {
  name = "${var.project_name}-vault-s3-policy"
  role = aws_iam_role.vault_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AccessRawBucket"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.raw_data.arn,
          "${aws_s3_bucket.raw_data.arn}/*"
        ]
      }
    ]
  })
}

# --- Refinery Role: read raw data + write anonymized data ---
resource "aws_iam_role" "refinery_role" {
  name               = "${var.project_name}-refinery-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = { Name = "${var.project_name}-refinery-role" }
}

resource "aws_iam_role_policy" "refinery_policy" {
  name = "${var.project_name}-refinery-s3-policy"
  role = aws_iam_role.refinery_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadRawData"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.raw_data.arn,
          "${aws_s3_bucket.raw_data.arn}/*"
        ]
      },
      {
        Sid      = "WriteAnonymizedData"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.anonymized_data.arn,
          "${aws_s3_bucket.anonymized_data.arn}/*"
        ]
      }
    ]
  })
}

# --- Lab Role: read ONLY anonymized data — NO access to raw ---
resource "aws_iam_role" "lab_role" {
  name               = "${var.project_name}-lab-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = { Name = "${var.project_name}-lab-role" }
}

resource "aws_iam_role_policy" "lab_policy" {
  name = "${var.project_name}-lab-s3-policy"
  role = aws_iam_role.lab_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAnonymizedOnly"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.anonymized_data.arn,
          "${aws_s3_bucket.anonymized_data.arn}/*"
        ]
      },
      {
        Sid      = "ExplicitDenyRawData"
        Effect   = "Deny"
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.raw_data.arn,
          "${aws_s3_bucket.raw_data.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lab_ssm" {
  role       = aws_iam_role.lab_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ─── Instance Profiles ─────────────────────────────────────────────────────

resource "aws_iam_instance_profile" "vault_profile" {
  name = "${var.project_name}-vault-profile"
  role = aws_iam_role.vault_role.name
}

resource "aws_iam_instance_profile" "refinery_profile" {
  name = "${var.project_name}-refinery-profile"
  role = aws_iam_role.refinery_role.name
}

resource "aws_iam_instance_profile" "lab_profile" {
  name = "${var.project_name}-lab-profile"
  role = aws_iam_role.lab_role.name
}

# ─── Outputs ───────────────────────────────────────────────────────────────

output "kms_key_arn"                    { value = aws_kms_key.data_key.arn }
output "kms_key_id"                     { value = aws_kms_key.data_key.key_id }
output "raw_data_bucket"                { value = aws_s3_bucket.raw_data.id }
output "anonymized_data_bucket"         { value = aws_s3_bucket.anonymized_data.id }
output "vault_instance_profile_name"    { value = aws_iam_instance_profile.vault_profile.name }
output "refinery_instance_profile_name" { value = aws_iam_instance_profile.refinery_profile.name }
output "lab_instance_profile_name"      { value = aws_iam_instance_profile.lab_profile.name }
output "vault_role_arn"                 { value = aws_iam_role.vault_role.arn }
output "refinery_role_arn"              { value = aws_iam_role.refinery_role.arn }
output "lab_role_arn"                   { value = aws_iam_role.lab_role.arn }
