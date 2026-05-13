###############################################################################
# Secure Medical Research City — Root Configuration
# Each module corresponds to one group member's responsibility.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ─────────────────────────────────────────────────────────────────────────────
# Member A — The Civil Engineer (Networking & VPC)
# ─────────────────────────────────────────────────────────────────────────────
module "networking" {
  source = "./modules/member_a_networking"

  project_name       = var.project_name
  vpc_cidr           = "10.0.0.0/16"
  vault_subnet_cidr  = "10.0.1.0/24"    # The Vault (Ingestion)
  refinery_subnet_cidr = "10.0.2.0/24"  # The Refinery (Processing)
  lab_subnet_cidr    = "10.0.3.0/24"    # The Lab (Analytics)
  availability_zone  = "${var.aws_region}a"
}

# ─────────────────────────────────────────────────────────────────────────────
# Member B — The Security Warden (IAM & Encryption)
# ─────────────────────────────────────────────────────────────────────────────
module "security" {
  source = "./modules/member_b_security"

  project_name    = var.project_name
  vault_subnet_id = module.networking.vault_subnet_id
  lab_subnet_id   = module.networking.lab_subnet_id
}

# ─────────────────────────────────────────────────────────────────────────────
# Member C — The Industrialist (Compute & Docker)
# ─────────────────────────────────────────────────────────────────────────────
module "compute" {
  source = "./modules/member_c_compute"

  project_name          = var.project_name
  vpc_id                = module.networking.vpc_id
  vault_subnet_id       = module.networking.vault_subnet_id
  refinery_subnet_id    = module.networking.refinery_subnet_id
  lab_subnet_id         = module.networking.lab_subnet_id
  vault_sg_id           = module.networking.vault_sg_id
  refinery_sg_id        = module.networking.refinery_sg_id
  lab_sg_id             = module.networking.lab_sg_id
  vault_instance_profile   = module.security.vault_instance_profile_name
  refinery_instance_profile = module.security.refinery_instance_profile_name
  lab_instance_profile     = module.security.lab_instance_profile_name
  kms_key_arn           = module.security.kms_key_arn
}

# ─────────────────────────────────────────────────────────────────────────────
# Member D — The Auditor (Monitoring & Testing)
# ─────────────────────────────────────────────────────────────────────────────
module "monitoring" {
  source = "./modules/member_d_monitoring"

  project_name = var.project_name
  vpc_id       = module.networking.vpc_id
  lab_sg_id    = module.networking.lab_sg_id
  vault_instance_private_ip = module.compute.vault_instance_private_ip
  lab_instance_id           = module.compute.lab_instance_id
}
