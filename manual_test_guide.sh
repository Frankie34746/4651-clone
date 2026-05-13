#!/bin/bash
###############################################################################
# Manual Testing Guide for Secure Medical Research City
#
# This script provides step-by-step manual tests to validate each layer
# of the privacy architecture.
###############################################################################

set -euo pipefail

PROJECT="med-research-city"

# Get outputs
VPC_ID=$(terraform output -raw vpc_id)
VAULT_IP=$(terraform output -raw vault_instance_ip)
LAB_INSTANCE=$(terraform output -raw lab_instance_id)
LAB_IP=$(terraform output -raw lab_instance_ip)
RAW_BUCKET=$(terraform output -raw raw_data_bucket)
ANON_BUCKET=$(terraform output -raw anonymized_data_bucket)
KMS_KEY=$(terraform output -raw kms_key_arn)

echo "═══════════════════════════════════════════════════════════════"
echo "MANUAL TESTING GUIDE"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Test 1: List all instances
echo "TEST 1: Verify all instances exist and are running"
echo "─────────────────────────────────────────────────────────────"
aws ec2 describe-instances --filters "Name=tag:Name,Values=${PROJECT}-*-instance" \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name,PrivateIpAddress,Tags[?Key==`Name`].Value|[0]]' \
  --output table
echo ""

# Test 2: Verify security groups
echo "TEST 2: Inspect Security Group Rules"
echo "─────────────────────────────────────────────────────────────"
echo ""
echo "Lab Security Group (should allow ONLY Refinery 10.0.2.0/24):"
VAULT_SG=$(terraform output -raw vault_sg_id 2>/dev/null)
LAB_SG=$(terraform output -raw lab_sg_id 2>/dev/null)
REFINERY_SG=$(terraform output -raw refinery_sg_id 2>/dev/null)

aws ec2 describe-security-groups --group-ids "$LAB_SG" \
  --query 'SecurityGroups[0].[GroupId, GroupName, IpPermissions[*].[IpProtocol, FromPort, ToPort, IpRanges[*].CidrIp]]' \
  --output text | head -20
echo ""

# Test 3: Verify NACLs
echo "TEST 3: Inspect Network ACLs (Rule 50 = Explicit DENY)"
echo "─────────────────────────────────────────────────────────────"
echo ""

LAB_SUBNET=$(terraform output -raw lab_subnet_id 2>/dev/null)
VAULT_SUBNET=$(terraform output -raw vault_subnet_id 2>/dev/null)

echo "Lab NACL (should have rule 50 DENY for 10.0.1.0/24):"
aws ec2 describe-network-acls --filters "Name=association.subnet-id,Values=$LAB_SUBNET" \
  --query 'NetworkAcls[0].Entries[?RuleNumber==`50` || RuleNumber==`100`].[RuleNumber, Action, CidrBlock, Protocol]' \
  --output table
echo ""

# Test 4: SSH into Lab and test connectivity
echo "TEST 4: Connectivity Test from Lab Instance"
echo "─────────────────────────────────────────────────────────────"
echo "MANUAL STEPS:"
echo "  1. SSH into Lab instance: aws ssm start-session --target $LAB_INSTANCE"
echo "  2. Try ping Vault ($VAULT_IP): ping -c 5 $VAULT_IP"
echo "  3. Expected: 100% packet loss (all packets REJECTED)"
echo "  4. Try port scan: nmap -p 22,80,443,8080 $VAULT_IP (if nmap available)"
echo ""

# Test 5: IAM policy test
echo "TEST 5: IAM Policy Test (Lab cannot access raw bucket)"
echo "─────────────────────────────────────────────────────────────"
echo "MANUAL STEPS:"
echo "  1. SSH into Lab instance: aws ssm start-session --target $LAB_INSTANCE"
echo "  2. Try to list raw data bucket: aws s3 ls $RAW_BUCKET"
echo "  3. Expected: Access Denied (ExplicitDenyS3 policy blocks it)"
echo "  4. Try to list anonymized bucket: aws s3 ls $ANON_BUCKET"
echo "  5. Expected: SUCCESS (Lab CAN read anonymized data)"
echo ""

# Test 6: KMS encryption test
echo "TEST 6: KMS Encryption Test"
echo "─────────────────────────────────────────────────────────────"
KEY_ID=$(echo "$KMS_KEY" | awk -F'/' '{print $NF}')
echo "KMS Key: $KEY_ID"
echo ""
echo "Check key properties:"
aws kms describe-key --key-id "$KEY_ID" \
  --query 'KeyMetadata.[KeyId, KeyState, Description, KeyUsage, Origin]' \
  --output text
echo ""
echo "Check key rotation:"
aws kms get-key-rotation-status --key-id "$KEY_ID" \
  --query 'KeyRotationEnabled' --output text
echo ""

# Test 7: S3 bucket encryption
echo "TEST 7: S3 Bucket Encryption Configuration"
echo "─────────────────────────────────────────────────────────────"
for BUCKET in "$RAW_BUCKET" "$ANON_BUCKET"; do
  echo ""
  echo "Bucket: $BUCKET"
  aws s3api get-bucket-encryption --bucket "$BUCKET" 2>/dev/null || echo "  (encryption not yet configured)"
done
echo ""

# Test 8: Flow logs
echo "TEST 8: VPC Flow Logs Status"
echo "─────────────────────────────────────────────────────────────"
aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$VPC_ID" \
  --query 'FlowLogs[].[FlowLogId, FlowLogStatus, LogDestinationType, LogDestination]' \
  --output table
echo ""

# Test 9: CloudWatch dashboard
echo "TEST 9: CloudWatch Dashboard & Alarms"
echo "─────────────────────────────────────────────────────────────"
DASHBOARD_URL=$(terraform output -raw cloudwatch_dashboard_url)
echo "Open dashboard: $DASHBOARD_URL"
echo ""
echo "CloudWatch alarms:"
aws cloudwatch describe-alarms --alarm-names "${PROJECT}-lab-vault-breach-attempt" \
  --query 'MetricAlarms[].[AlarmName, StateValue, StateReason]' \
  --output table
echo ""

# Test 10: Automatic penetration test
echo "TEST 10: Automated Penetration Test"
echo "─────────────────────────────────────────────────────────────"
echo "Run: ./penetration_test_runner.sh"
echo ""
echo "This script will:"
echo "  - Send SSM command to Lab instance"
echo "  - Execute ping and port scan to Vault ($VAULT_IP)"
echo "  - Expected: 100% packet loss, all ports BLOCKED"
echo "  - Shows CloudWatch dashboard URL with REJECT logs"
echo ""

# Summary
echo "═══════════════════════════════════════════════════════════════"
echo "TESTING CHECKLIST"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Infrastructure:"
echo "  [ ] All 3 instances running (Vault, Refinery, Lab)"
echo "  [ ] VPC exists with 3 subnets (10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24)"
echo ""
echo "Network Isolation:"
echo "  [ ] Lab SG allows only Refinery CIDR (10.0.2.0/24)"
echo "  [ ] Lab NACL has explicit DENY rule 50 for Vault CIDR"
echo "  [ ] Ping from Lab to Vault returns 100% packet loss"
echo "  [ ] Port scans from Lab to Vault all return BLOCKED"
echo ""
echo "IAM Enforcement:"
echo "  [ ] Lab IAM role has ExplicitDeny on raw data S3 bucket"
echo "  [ ] Lab can read from anonymized data bucket"
echo "  [ ] Lab CANNOT read from raw data bucket (Access Denied)"
echo ""
echo "Encryption:"
echo "  [ ] KMS key provisioned and rotation enabled"
echo "  [ ] Both S3 buckets use KMS encryption"
echo "  [ ] EBS volumes on all instances encrypted with KMS key"
echo ""
echo "Monitoring:"
echo "  [ ] VPC Flow Logs active and capturing traffic"
echo "  [ ] CloudWatch alarms configured for breach attempts"
echo "  [ ] Dashboard shows rejected Lab→Vault traffic"
echo ""
echo "Data Pipeline:"
echo "  [ ] Vault instance ingests raw patient records"
echo "  [ ] Refinery anonymizes data (removes names)"
echo "  [ ] Lab analytics runs on anonymized data only"
echo ""
