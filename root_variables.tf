variable "project_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "med-research-city"
}

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}
