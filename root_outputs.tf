output "vpc_id" {
  value = module.networking.vpc_id
}

output "vault_subnet_id" {
  value = module.networking.vault_subnet_id
}

output "refinery_subnet_id" {
  value = module.networking.refinery_subnet_id
}

output "lab_subnet_id" {
  value = module.networking.lab_subnet_id
}

output "vault_sg_id" {
  value = module.networking.vault_sg_id
}

output "refinery_sg_id" {
  value = module.networking.refinery_sg_id
}

output "lab_sg_id" {
  value = module.networking.lab_sg_id
}

output "vault_instance_id" {
  value = module.compute.vault_instance_id
}

output "vault_instance_ip" {
  value = module.compute.vault_instance_private_ip
}

output "lab_instance_id" {
  value = module.compute.lab_instance_id
}

output "lab_instance_ip" {
  value = module.compute.lab_instance_private_ip
}

output "raw_data_bucket" {
  value = module.security.raw_data_bucket
}

output "anonymized_data_bucket" {
  value = module.security.anonymized_data_bucket
}

output "cloudwatch_dashboard_url" {
  value = module.monitoring.dashboard_url
}

output "kms_key_arn" {
  value     = module.security.kms_key_arn
  sensitive = true
}
