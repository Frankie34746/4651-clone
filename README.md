# Secure Medical Research City

A Terraform-based infrastructure skeleton implementing **network-level data privacy** for medical research. Three isolated subnets enforce a one-way data pipeline: raw patient records are ingested, anonymized, and only then made available to researchers.

## Updates (May 8, 2026)

✅ **Fixed Issues:**
- Reorganized Terraform files into proper module structure (`modules/member_a_networking/`, `member_b_security/`, `member_c_compute/`, `member_d_monitoring/`)
- Fixed non-ASCII character in Lab security group description (em-dash → hyphen)
- Fixed penetration test script to use correct Terraform outputs (`lab_instance_id` instead of `lab_instance_ip`)
- Added comprehensive AWS output exports for all test scripts

✅ **New Test Suites:**
- `comprehensive_test.sh` — 9 automated infrastructure validation tests
- `manual_test_guide.sh` — Step-by-step manual testing guide with AWS CLI commands
- `penetration_test_runner.sh` — Automated network isolation proof (fixed output references)

✅ **Documentation:**
- Updated README with project structure, prerequisites, and full testing guide
- Added AWS credential setup instructions (IAM, SSO, AWS Academy)
- Added deployment validation checklist and troubleshooting guide

## Architecture

```
┌─────────────────────── VPC 10.0.0.0/16 ───────────────────────┐
│                                                                 │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐    │
│  │  THE VAULT   │───▶│ THE REFINERY  │───▶│    THE LAB      │    │
│  │  10.0.1.0/24 │    │  10.0.2.0/24  │    │  10.0.3.0/24    │    │
│  │              │    │               │    │                 │    │
│  │ Raw patient  │    │ Anonymization │    │ Spark analytics │    │
│  │ records      │    │ Docker svc    │    │ on clean data   │    │
│  │ (encrypted)  │    │               │    │                 │    │
│  └─────────────┘    └──────────────┘    └─────────────────┘    │
│         ▲                                        │              │
│         │            ╔═══════════╗                │              │
│         └────────────║  BLOCKED  ║◀───────────────┘              │
│                      ╚═══════════╝                              │
│                                                                 │
│  ┌────────────┐  ┌────────────────┐  ┌────────────────────┐    │
│  │ IAM + KMS  │  │ EC2/Docker     │  │ Flow Logs + CW     │    │
│  │ Member B   │  │ Member C       │  │ Member D           │    │
│  └────────────┘  └────────────────┘  └────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
              Networking & VPC — Member A
```

## Team Responsibilities

| Member | Role | Module | Key Deliverables |
|--------|------|--------|-----------------|
| **A** | Civil Engineer | `modules/member_a_networking/` | VPC, 3 subnets, route tables, NACLs, security groups |
| **B** | Security Warden | `modules/member_b_security/` | IAM roles (least privilege), KMS key, S3 bucket encryption |
| **C** | Industrialist | `modules/member_c_compute/` | EC2 instances, Docker containers, Spark setup |
| **D** | Auditor | `modules/member_d_monitoring/` | VPC Flow Logs, CloudWatch dashboard, pen-test SSM document |

## Privacy Enforcement (Layered)

The "Lab cannot reach the Vault" rule is enforced at **four layers**:

1. **Network ACLs** — Lab NACL has an explicit DENY rule (rule 50) for Vault CIDR `10.0.1.0/24` on both ingress and egress.
2. **Security Groups** — Lab SG only allows traffic from the Refinery CIDR. No Vault CIDR is listed.
3. **IAM Policies** — Lab IAM role has an explicit `Deny` on all S3 actions against the raw-data bucket.
4. **KMS Conditions** — Lab can only decrypt data tagged with `data_class=anonymized`.

## Project Structure

```
.
├── root_main.tf              # Main Terraform configuration (orchestrates 4 modules)
├── root_variables.tf         # Root variables (project_name, aws_region)
├── root_outputs.tf           # Aggregated outputs from all modules
├── modules/
│   ├── member_a_networking/  # VPC, subnets, route tables, NACLs, security groups
│   ├── member_b_security/    # IAM roles, KMS key, S3 buckets
│   ├── member_c_compute/     # EC2 instances with Docker/Spark
│   └── member_d_monitoring/  # VPC Flow Logs, CloudWatch, SSM pen-test document
├── penetration_test_runner.sh    # Automated penetration test script
├── comprehensive_test.sh         # Full infrastructure validation (9 automated tests)
├── manual_test_guide.sh          # Step-by-step manual testing guide
└── README.md                     # This file
```

## Prerequisites

### AWS Credentials
You must configure AWS credentials before running Terraform. Choose one method:

**Option 1: AWS IAM User (Recommended for personal AWS)**
```bash
aws configure
# Enter:
#   Access Key ID
#   Secret Access Key
#   Default region (e.g., us-east-1)
#   Default output format: json
```

**Option 2: AWS SSO**
```bash
aws configure sso
# Follow prompts for SSO setup
aws sso login --profile <profile_name>
export AWS_PROFILE=<profile_name>
```

**Option 3: AWS Academy / Temporary Credentials**
```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
export AWS_REGION=us-east-1
```

Verify credentials work:
```bash
aws sts get-caller-identity
```

## Quick Start

```bash
# 1. Ensure AWS credentials are configured
aws sts get-caller-identity

# 2. Initialize Terraform (downloads providers, validates modules)
terraform init

# 3. Review the deployment plan
terraform plan

# 4. Deploy infrastructure (creates VPC, EC2, IAM, KMS, S3, CloudWatch)
terraform apply

# 5. Wait 3-5 minutes for EC2 instances to finish initialization

# 6. Run comprehensive test suite
chmod +x comprehensive_test.sh
./comprehensive_test.sh

# 7. Verify infrastructure and run manual tests
chmod +x manual_test_guide.sh
./manual_test_guide.sh

# 8. Run penetration test (network isolation proof)
chmod +x penetration_test_runner.sh
./penetration_test_runner.sh

# 9. Check CloudWatch dashboard for REJECT logs
# Dashboard URL printed by penetration_test_runner.sh and in: terraform output -raw cloudwatch_dashboard_url
```

## Testing & Validation

This repo includes a comprehensive testing suite to validate all four security layers:

### Test 1: Automated Infrastructure Tests
```bash
./comprehensive_test.sh
```
Runs 9 automated checks:
- VPC, subnets, and security groups exist
- Lab security group DENIES Vault CIDR
- Network ACLs have explicit DENY rules (rule 50)
- IAM policies prevent Lab from accessing raw data bucket
- KMS key exists and has automatic rotation enabled
- S3 buckets are encrypted with KMS
- VPC Flow Logs are active
- CloudWatch dashboard and alarms are configured
- Instance user data scripts executed successfully

### Test 2: Manual Step-by-Step Validation
```bash
./manual_test_guide.sh
```
Displays:
- All EC2 instances and their IPs
- Security group rules and NACLs
- IAM role information
- KMS key configuration
- S3 bucket details
- Manual test steps (SSH, connectivity tests, S3 access tests)

### Test 3: Network Isolation Penetration Test
```bash
./penetration_test_runner.sh
```
Proves network isolation by:
- Sending SSM command to Lab instance
- Attempting ICMP ping to Vault instance (should fail)
- Attempting TCP port scans to Vault (should all be BLOCKED)
- Displaying CloudWatch dashboard with rejected traffic logs

**Expected result: 100% packet loss, all ports BLOCKED**

## Deployment Validation Checklist

After `terraform apply`, verify:

### ✅ Infrastructure
- [ ] Run `./comprehensive_test.sh` → all tests pass
- [ ] 3 EC2 instances running (Vault, Refinery, Lab)
- [ ] VPC with 3 subnets (10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24)
- [ ] Security groups and NACLs configured

### ✅ Network Isolation
- [ ] Lab security group allows ONLY Refinery CIDR (10.0.2.0/24)
- [ ] Lab NACL has explicit DENY (rule 50) for Vault CIDR
- [ ] Run `./penetration_test_runner.sh` → 100% packet loss on ping
- [ ] CloudWatch shows rejected Lab→Vault traffic

### ✅ IAM Enforcement
- [ ] Lab IAM role has explicit DENY on raw data bucket
- [ ] Lab can list anonymized data bucket
- [ ] Lab CANNOT list raw data bucket (Access Denied)

### ✅ Encryption
- [ ] KMS key provisioned with automatic rotation
- [ ] Both S3 buckets use KMS encryption (aws:kms)
- [ ] EBS volumes on all instances encrypted with KMS key

### ✅ Data Pipeline
- [ ] Vault instance ingests raw patient records to `/data/raw/`
- [ ] Refinery anonymizes data, strips PII, writes to `/data/anonymized/`
- [ ] Lab runs Spark analytics on anonymized data only
- [ ] Lab instance has NO access to raw data

## Troubleshooting

### `terraform init` fails with module not found
Ensure all module directories exist:
```bash
mkdir -p modules/member_a_networking
mkdir -p modules/member_b_security
mkdir -p modules/member_c_compute
mkdir -p modules/member_d_monitoring
```

### `terraform plan` reports no AWS credentials
Configure AWS credentials using one of the methods in [Prerequisites](#prerequisites).

### Test scripts fail with "Output not found"
Run `terraform apply` to update the Terraform state with all outputs:
```bash
terraform apply -auto-approve
```

### SSM command fails (InvalidInstanceId)
Ensure the Lab instance is running and has SSM permissions (included in the IAM role). Wait 2-3 minutes after `terraform apply` for instance initialization.

### Instances not initializing (user data not running)
- Wait 5 minutes after `terraform apply`
- Check instance system log: `aws ec2 get-console-output --instance-id <instance-id>`
- Look for Docker installation and container startup messages

## Cleanup

```bash
terraform destroy
```

This removes:
- VPC, subnets, route tables, NACLs, security groups
- EC2 instances
- IAM roles and instance profiles
- KMS key
- S3 buckets
- CloudWatch log groups, dashboards, and alarms
- SSM documents
