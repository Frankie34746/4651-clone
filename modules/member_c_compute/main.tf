###############################################################################
# MEMBER C — The Industrialist
# Compute: EC2 Instances with Docker + Spark (one-click setup)
#
# DESIGN PRINCIPLE:
#   - Vault instance: receives raw patient data via ingestion scripts.
#   - Refinery instance: runs a Docker container that anonymizes data.
#   - Lab instance: runs Apache Spark in Docker for analytics on clean data.
#   - All EBS volumes encrypted with the shared KMS key.
###############################################################################

variable "project_name"            { type = string }
variable "vpc_id"                  { type = string }
variable "vault_subnet_id"         { type = string }
variable "refinery_subnet_id"      { type = string }
variable "lab_subnet_id"           { type = string }
variable "vault_sg_id"             { type = string }
variable "refinery_sg_id"          { type = string }
variable "lab_sg_id"               { type = string }
variable "vault_instance_profile"  { type = string }
variable "refinery_instance_profile" { type = string }
variable "lab_instance_profile"    { type = string }
variable "kms_key_arn"             { type = string }

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

# Latest Amazon Linux 2023 AMI
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ─── User Data Scripts (Docker + App Bootstrap) ────────────────────────────

locals {
  # Common Docker installation (Amazon Linux 2023)
  docker_install = <<-SCRIPT
    #!/bin/bash
    set -euo pipefail
    dnf update -y
    dnf install -y docker
    systemctl enable docker && systemctl start docker
    usermod -aG docker ec2-user
  SCRIPT

  # Vault: simple ingestion service container
  vault_user_data = <<-SCRIPT
    ${local.docker_install}

    # Pull a lightweight Python image for the ingestion service
    docker pull python:3.11-slim

    # Create a sample ingestion script
    mkdir -p /opt/vault
    cat > /opt/vault/ingest.py << 'PYEOF'
    """
    Vault Ingestion Service — receives raw patient records.
    In production this would listen on a port or poll an SQS queue.
    """
    import json, os, datetime

    SAMPLE_RECORDS = [
        {"patient_id": "P001", "name": "Alice Smith",   "medical_history": "Diabetes Type 2"},
        {"patient_id": "P002", "name": "Bob Johnson",   "medical_history": "Hypertension"},
        {"patient_id": "P003", "name": "Carol Williams", "medical_history": "Asthma"},
    ]

    OUTPUT_DIR = "/data/raw"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for record in SAMPLE_RECORDS:
        fname = f"{OUTPUT_DIR}/{record['patient_id']}_{datetime.datetime.now().isoformat()}.json"
        with open(fname, 'w') as f:
            json.dump(record, f)
        print(f"[VAULT] Ingested: {record['patient_id']}")

    print("[VAULT] Ingestion complete.")
    PYEOF

    docker run --rm -v /opt/vault:/app -v /data:/data python:3.11-slim \
      python /app/ingest.py
    echo "[VAULT INSTANCE READY]"
  SCRIPT

  # Refinery: anonymization container
  refinery_user_data = <<-SCRIPT
    ${local.docker_install}

    docker pull python:3.11-slim

    mkdir -p /opt/refinery
    cat > /opt/refinery/anonymize.py << 'PYEOF'
    """
    Refinery Anonymization Service
    Reads raw records, strips PII (name, patient_id), writes clean data.
    One-way pipeline: raw → anonymized.
    """
    import json, os, hashlib, glob

    RAW_DIR   = "/data/raw"
    CLEAN_DIR = "/data/anonymized"
    os.makedirs(CLEAN_DIR, exist_ok=True)

    for fpath in glob.glob(f"{RAW_DIR}/*.json"):
        with open(fpath) as f:
            record = json.load(f)

        # Anonymize: hash the ID, remove the name entirely
        anon_record = {
            "anon_id": hashlib.sha256(record["patient_id"].encode()).hexdigest()[:12],
            "medical_history": record["medical_history"],
            # Name is DROPPED — never leaves the Vault
        }

        out_name = os.path.basename(fpath).replace(".json", "_anon.json")
        with open(f"{CLEAN_DIR}/{out_name}", 'w') as f:
            json.dump(anon_record, f)
        print(f"[REFINERY] Anonymized: {record['patient_id']} → {anon_record['anon_id']}")

    print("[REFINERY] Anonymization pipeline complete.")
    PYEOF

    docker run --rm -v /opt/refinery:/app -v /data:/data python:3.11-slim \
      python /app/anonymize.py
    echo "[REFINERY INSTANCE READY]"
  SCRIPT

  # Lab: Spark analytics container
  lab_user_data = <<-SCRIPT
    ${local.docker_install}

    # Install and start the SSM agent so this private Lab instance can register with Systems Manager
    dnf install -y amazon-ssm-agent
    systemctl enable amazon-ssm-agent
    systemctl start amazon-ssm-agent

    # Pull Spark image (Bitnami's lightweight Spark)
    docker pull bitnami/spark:3.5

    mkdir -p /opt/lab
    cat > /opt/lab/analyze.py << 'PYEOF'
    """
    Lab Analytics — Spark job on anonymized data only.
    This instance CANNOT reach the Vault or see raw patient names.
    """
    from pyspark.sql import SparkSession

    spark = SparkSession.builder \
    .appName("MedResearchAnalytics") \
    .master("local[*]") \
    .getOrCreate()

    # Read anonymized JSON files
    df = spark.read.json("/data/anonymized/")

    print("=== ANONYMIZED DATA SCHEMA ===")
    df.printSchema()

    print("=== SAMPLE ANONYMIZED RECORDS ===")
    df.show(truncate=False)

    print("=== CONDITION FREQUENCY ===")
    df.groupBy("medical_history").count().show()

    # VERIFY: no 'name' or 'patient_id' columns exist
    assert "name" not in df.columns, "PRIVACY VIOLATION: 'name' found in Lab data!"
    assert "patient_id" not in df.columns, "PRIVACY VIOLATION: 'patient_id' found in Lab data!"
    print("[LAB] Privacy check PASSED — no PII in analytics dataset.")

    spark.stop()
    PYEOF

    # Run Spark job inside Docker
    docker run --rm \
    -v /opt/lab:/app \
    -v /data:/data \
    bitnami/spark:3.5 \
    spark-submit --master local[*] /app/analyze.py

    echo "[LAB INSTANCE READY — SPARK ANALYTICS OPERATIONAL]"
  SCRIPT
}

# ─── EC2 Instances ─────────────────────────────────────────────────────────

resource "aws_instance" "vault" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = var.vault_subnet_id
  vpc_security_group_ids = [var.vault_sg_id]
  iam_instance_profile   = var.vault_instance_profile
  user_data_base64       = base64encode(local.vault_user_data)

  root_block_device {
    volume_size = 8
    volume_type = "gp2"
    encrypted   = true
    kms_key_id  = var.kms_key_arn
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 enforced
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${var.project_name}-vault-instance"
  }
}

resource "aws_instance" "refinery" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = var.refinery_subnet_id
  vpc_security_group_ids = [var.refinery_sg_id]
  iam_instance_profile   = var.refinery_instance_profile
  user_data_base64       = base64encode(local.refinery_user_data)

  root_block_device {
    volume_size = 8
    volume_type = "gp2"
    encrypted   = true
    kms_key_id  = var.kms_key_arn
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${var.project_name}-refinery-instance"
  }
}

resource "aws_instance" "lab" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro" # Spark needs more resources
  subnet_id              = var.lab_subnet_id
  vpc_security_group_ids = [var.lab_sg_id]
  iam_instance_profile   = var.lab_instance_profile
  user_data_base64       = base64encode(local.lab_user_data)

  root_block_device {
    volume_size = 8
    volume_type = "gp2"
    encrypted   = true
    kms_key_id  = var.kms_key_arn
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${var.project_name}-lab-spark-instance"
  }
}

# ─── Outputs ───────────────────────────────────────────────────────────────

output "vault_instance_id" {
  value = aws_instance.vault.id
}

output "vault_instance_private_ip" {
  value = aws_instance.vault.private_ip
}

output "refinery_instance_id" {
  value = aws_instance.refinery.id
}

output "lab_instance_id" {
  value = aws_instance.lab.id
}

output "lab_instance_private_ip" {
  value = aws_instance.lab.private_ip
}