#!/bin/bash
###############################################################################
# run_pentest.sh — Execute the Lab→Vault penetration test
#
# Usage: ./scripts/run_pentest.sh
#
# Prerequisites:
#   - Terraform has been applied (all resources exist)
#   - AWS CLI configured with appropriate credentials
#   - SSM Agent running on the Lab instance
###############################################################################

set -euo pipefail

PROJECT="med-research-city"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Secure Medical Research City — Penetration Test Runner    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Get instance IDs from Terraform output
LAB_INSTANCE_ID=$(terraform output -raw lab_instance_id 2>/dev/null || echo "")
VAULT_IP=$(terraform output -raw vault_instance_ip 2>/dev/null || echo "")

if [ -z "$LAB_INSTANCE_ID" ] || [ -z "$VAULT_IP" ]; then
  echo "[ERROR] Could not read Terraform outputs. Run 'terraform apply' first."
  exit 1
fi

echo "[1/3] Sending penetration test command to Lab instance..."
echo "       Lab Instance: $LAB_INSTANCE_ID"
echo "       Target (Vault): $VAULT_IP"
echo ""

COMMAND_ID=$(aws ssm send-command \
  --document-name "${PROJECT}-pentest-lab-to-vault" \
  --targets "Key=instanceids,Values=$LAB_INSTANCE_ID" \
  --query "Command.CommandId" \
  --output text)

echo "[2/3] Command sent (ID: $COMMAND_ID). Waiting for results..."
sleep 10

echo "[3/3] Fetching results..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

aws ssm get-command-invocation \
  --command-id "$COMMAND_ID" \
  --instance-id "$LAB_INSTANCE_ID" \
  --query "StandardOutputContent" \
  --output text 2>/dev/null || echo "[Waiting... run again in 30 seconds]"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "[DONE] Check the CloudWatch dashboard for REJECT flow logs:"
echo "       https://console.aws.amazon.com/cloudwatch/home#dashboards:name=${PROJECT}-security"
