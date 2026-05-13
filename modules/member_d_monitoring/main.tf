###############################################################################
# MEMBER D — The Auditor
# Monitoring: VPC Flow Logs, CloudWatch Dashboard, Penetration Test Proof
#
# DESIGN PRINCIPLE:
#   - VPC Flow Logs capture ALL network traffic (accepted + rejected).
#   - CloudWatch Dashboard visualizes rejected traffic Lab → Vault.
#   - A penetration test (ping from Lab to Vault) is scripted;
#     the logs prove it was REJECTED.
###############################################################################

variable "project_name"              { type = string }
variable "vpc_id"                    { type = string }
variable "lab_sg_id"                 { type = string }
variable "vault_instance_private_ip" { type = string }
variable "lab_instance_id"           { type = string }

# ─── IAM Role for VPC Flow Logs ────────────────────────────────────────────

resource "aws_iam_role" "flow_log_role" {
  name = "${var.project_name}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "${var.project_name}-flow-log-policy"
  role = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

# ─── CloudWatch Log Group ──────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/vpc/${var.project_name}/flow-logs"
  retention_in_days = 30

  tags = { Name = "${var.project_name}-flow-logs" }
}

# ─── VPC Flow Logs (capture ALL traffic including REJECT) ──────────────────

resource "aws_flow_log" "vpc_flow_log" {
  vpc_id          = var.vpc_id
  traffic_type    = "ALL"  # Captures both ACCEPT and REJECT
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn

  tags = { Name = "${var.project_name}-vpc-flow-log" }
}

# ─── CloudWatch Metric Filter: Count REJECTED Packets ──────────────────────

resource "aws_cloudwatch_log_metric_filter" "rejected_traffic" {
  name           = "${var.project_name}-rejected-lab-to-vault"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name

  # Flow log format: <version> <account-id> <interface-id> <srcaddr> <dstaddr>
  # <srcport> <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>
  # We filter for action=REJECT and destination in Vault subnet (10.0.1.*)
  pattern = "[version, account, eni, srcaddr, dstaddr=\"10.0.1.*\", srcport, dstport, protocol, packets, bytes, start, end, action=\"REJECT\", status]"

  metric_transformation {
    name          = "RejectedLabToVaultPackets"
    namespace     = "${var.project_name}/Security"
    value         = "$packets"
    default_value = 0
  }
}

# ─── CloudWatch Alarm: Alert on Any Lab→Vault Attempt ──────────────────────

resource "aws_cloudwatch_metric_alarm" "lab_vault_breach_alarm" {
  alarm_name          = "${var.project_name}-lab-vault-breach-attempt"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RejectedLabToVaultPackets"
  namespace           = "${var.project_name}/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "ALERT: Lab subnet attempted to reach Vault subnet — traffic was REJECTED"
  treat_missing_data  = "notBreaching"

  tags = { Name = "${var.project_name}-breach-alarm" }
}

# ─── CloudWatch Dashboard ──────────────────────────────────────────────────

resource "aws_cloudwatch_dashboard" "security_dashboard" {
  dashboard_name = "${var.project_name}-security"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Rejected Packets: Lab → Vault (Privacy Wall)"
          metrics = [
            ["${var.project_name}/Security", "RejectedLabToVaultPackets", { stat = "Sum", period = 60 }]
          ]
          view    = "timeSeries"
          region  = "us-east-1"
          yAxis   = { left = { min = 0 } }
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Recent REJECT Events (Lab → Vault)"
          query  = <<-EOQ
            fields @timestamp, srcaddr, dstaddr, action
            | filter action = "REJECT" and dstaddr like "10.0.1."
            | sort @timestamp desc
            | limit 20
          EOQ
          region = "us-east-1"
          view   = "table"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "All VPC Traffic: Accept vs Reject"
          metrics = [
            ["${var.project_name}/Security", "RejectedLabToVaultPackets", { stat = "Sum", period = 300, label = "Rejected" }]
          ]
          view    = "bar"
          region  = "us-east-1"
        }
      },
      {
        type   = "text"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          markdown = <<-MD
            ## Penetration Test Results
            **Test**: `ping ${var.vault_instance_private_ip}` from Lab instance
            **Expected**: 100% packet loss (REJECT at NACL + Security Group)
            **Dashboard**: This panel shows rejected packets proving isolation.

            ### How to run the test:
            ```bash
            aws ssm send-command \
              --instance-ids "${var.lab_instance_id}" \
              --document-name "AWS-RunShellScript" \
              --parameters 'commands=["ping -c 5 ${var.vault_instance_private_ip}"]'
            ```
          MD
        }
      }
    ]
  })
}

# ─── SSM Document: Automated Penetration Test ──────────────────────────────
# Runs from the Lab instance, tries to ping the Vault. Should FAIL.

resource "aws_ssm_document" "pentest" {
  name            = "${var.project_name}-pentest-lab-to-vault"
  document_type   = "Command"
  document_format = "YAML"

  content = yamlencode({
    schemaVersion = "2.2"
    description   = "Penetration test: attempt ping from Lab to Vault (should fail)"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "PingVaultFromLab"
      inputs = {
        runCommand = [
          "echo '=== PENETRATION TEST: Lab → Vault ==='",
          "echo 'Target: ${var.vault_instance_private_ip} (Vault subnet 10.0.1.x)'",
          "echo 'Expected: 100% packet loss (REJECTED by NACLs and SGs)'",
          "echo ''",
          "echo '--- ICMP Ping Test ---'",
          "ping -c 5 -W 2 ${var.vault_instance_private_ip} || true",
          "echo ''",
          "echo '--- TCP Port Scan (common ports) ---'",
          "for port in 22 80 443 8080; do",
          "  timeout 2 bash -c \"echo >/dev/tcp/${var.vault_instance_private_ip}/$port\" 2>/dev/null && echo \"PORT $port: OPEN (BREACH!)\" || echo \"PORT $port: BLOCKED (PASS)\"",
          "done",
          "echo ''",
          "echo '=== TEST COMPLETE ==='",
          "echo 'If all connections failed, the privacy wall is working correctly.'"
        ]
      }
    }]
  })

  tags = { Name = "${var.project_name}-pentest-document" }
}

# ─── Outputs ───────────────────────────────────────────────────────────────

output "flow_log_group_name" {
  value = aws_cloudwatch_log_group.flow_logs.name
}

output "dashboard_url" {
  value = "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=${var.project_name}-security"
}

output "pentest_document_name" {
  value = aws_ssm_document.pentest.name
}

output "alarm_name" {
  value = aws_cloudwatch_metric_alarm.lab_vault_breach_alarm.alarm_name
}
