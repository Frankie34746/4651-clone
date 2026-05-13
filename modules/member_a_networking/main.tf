###############################################################################
# MEMBER A — The Civil Engineer
# Networking: VPC, Subnets, Route Tables, NACLs, Security Groups
#
# DESIGN PRINCIPLE:
#   The Vault (10.0.1.0/24) and The Lab (10.0.3.0/24) have NO direct route.
#   Only The Refinery (10.0.2.0/24) can talk to both — and it pushes data
#   one-way: Vault → Refinery → Lab.
###############################################################################

# ─── Variables ───────────────────────────────────────────────────────────────

variable "project_name"        { type = string }
variable "vpc_cidr"            { type = string }
variable "vault_subnet_cidr"   { type = string }
variable "refinery_subnet_cidr" { type = string }
variable "lab_subnet_cidr"     { type = string }
variable "availability_zone"   { type = string }

data "aws_region" "current" {}

# ─── VPC ─────────────────────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

# ─── Subnets (Three Neighborhoods) ──────────────────────────────────────────

resource "aws_subnet" "vault" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.vault_subnet_cidr
  availability_zone = var.availability_zone

  tags = { Name = "${var.project_name}-vault-subnet" }
}

resource "aws_subnet" "refinery" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.refinery_subnet_cidr
  availability_zone = var.availability_zone

  tags = { Name = "${var.project_name}-refinery-subnet" }
}

resource "aws_subnet" "lab" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.lab_subnet_cidr
  availability_zone = var.availability_zone

  tags = { Name = "${var.project_name}-lab-subnet" }
}

# ─── Route Tables ────────────────────────────────────────────────────────────
# KEY ISOLATION: Each subnet gets its own route table.
# The Lab's route table has NO route to the Vault CIDR.
# The Vault's route table has NO route to the Lab CIDR.
# Only the Refinery has routes to both.

resource "aws_route_table" "vault_rt" {
  vpc_id = aws_vpc.main.id
  # Only local VPC route (auto-added) + route to Refinery
  tags = { Name = "${var.project_name}-vault-rt" }
}

resource "aws_route_table" "refinery_rt" {
  vpc_id = aws_vpc.main.id
  # Refinery can reach both Vault and Lab (via local VPC routing)
  tags = { Name = "${var.project_name}-refinery-rt" }
}

resource "aws_route_table" "lab_rt" {
  vpc_id = aws_vpc.main.id
  # Lab can only reach Refinery — NO route to Vault
  tags = { Name = "${var.project_name}-lab-rt" }
}

resource "aws_route_table_association" "vault" {
  subnet_id      = aws_subnet.vault.id
  route_table_id = aws_route_table.vault_rt.id
}

resource "aws_route_table_association" "refinery" {
  subnet_id      = aws_subnet.refinery.id
  route_table_id = aws_route_table.refinery_rt.id
}

resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab_rt.id
}

# ─── Network ACLs (Hard Firewall Between Neighborhoods) ─────────────────────

# VAULT NACL: allow traffic from Refinery only; DENY Lab entirely
resource "aws_network_acl" "vault_nacl" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.vault.id]

  # Allow inbound from Refinery
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.refinery_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # DENY inbound from Lab (explicit)
  ingress {
    protocol   = "-1"
    rule_no    = 50
    action     = "deny"
    cidr_block = var.lab_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # Allow all outbound to Refinery
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.refinery_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # DENY outbound to Lab
  egress {
    protocol   = "-1"
    rule_no    = 50
    action     = "deny"
    cidr_block = var.lab_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # Default: allow remaining (for ephemeral ports, etc.)
  ingress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.project_name}-vault-nacl" }
}

# LAB NACL: allow traffic from Refinery only; DENY Vault entirely
resource "aws_network_acl" "lab_nacl" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.lab.id]

  # DENY inbound from Vault (explicit — rule evaluated first)
  ingress {
    protocol   = "-1"
    rule_no    = 50
    action     = "deny"
    cidr_block = var.vault_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # Allow inbound from Refinery
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.refinery_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # DENY outbound to Vault
  egress {
    protocol   = "-1"
    rule_no    = 50
    action     = "deny"
    cidr_block = var.vault_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # Allow outbound to Refinery
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.refinery_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # Default allow remaining
  ingress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.project_name}-lab-nacl" }
}

# REFINERY NACL: can talk to both — it's the bridge
resource "aws_network_acl" "refinery_nacl" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.refinery.id]

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.project_name}-refinery-nacl" }
}
resource "aws_security_group" "ssm_endpoints_sg" {
  name_prefix = "${var.project_name}-ssm-endpoint-"
  description = "Allow VPC traffic to SSM interface endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow SSM endpoint access from inside VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Allow endpoint traffic to AWS service IPs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-ssm-endpoints-sg" }
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.ssm"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.lab.id]
  security_group_ids = [aws_security_group.ssm_endpoints_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.lab.id]
  security_group_ids = [aws_security_group.ssm_endpoints_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.lab.id]
  security_group_ids = [aws_security_group.ssm_endpoints_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [
    aws_route_table.vault_rt.id,
    aws_route_table.refinery_rt.id,
    aws_route_table.lab_rt.id,
  ]
}

# ─── Security Groups ────────────────────────────────────────────────────────

resource "aws_security_group" "vault_sg" {
  name_prefix = "${var.project_name}-vault-"
  description = "Vault: accept from Refinery only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "All traffic from Refinery subnet"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.refinery_subnet_cidr]
  }

  egress {
    description = "Outbound to Refinery only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.refinery_subnet_cidr]
  }

  tags = { Name = "${var.project_name}-vault-sg" }
}

resource "aws_security_group" "refinery_sg" {
  name_prefix = "${var.project_name}-refinery-"
  description = "Refinery: accept from Vault and Lab"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "From Vault"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vault_subnet_cidr]
  }

  ingress {
    description = "From Lab"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.lab_subnet_cidr]
  }

  egress {
    description = "To Vault and Lab"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${var.project_name}-refinery-sg" }
}

resource "aws_security_group" "lab_sg" {
  name_prefix = "${var.project_name}-lab-"
  description = "Lab: accept from Refinery only - NO Vault access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "All traffic from Refinery subnet"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.refinery_subnet_cidr]
  }

  # Spark UI port for researchers within the Lab subnet
  ingress {
    description = "Spark UI within Lab"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    self        = true
  }

  egress {
    description = "Outbound to Refinery only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.refinery_subnet_cidr]
  }

  tags = { Name = "${var.project_name}-lab-sg" }
}

# ─── Outputs ────────────────────────────────────────────────────────────────

output "vpc_id"             { value = aws_vpc.main.id }
output "vault_subnet_id"    { value = aws_subnet.vault.id }
output "refinery_subnet_id" { value = aws_subnet.refinery.id }
output "lab_subnet_id"      { value = aws_subnet.lab.id }
output "vault_sg_id"        { value = aws_security_group.vault_sg.id }
output "refinery_sg_id"     { value = aws_security_group.refinery_sg.id }
output "lab_sg_id"          { value = aws_security_group.lab_sg.id }
