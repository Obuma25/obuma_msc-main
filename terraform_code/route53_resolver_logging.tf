# Route 53 Resolver Query Logging for GuardDuty DNS Detection
# Required for GuardDuty to analyze DNS query domain names

# CloudWatch Log Group for Route 53 Resolver query logs
resource "aws_cloudwatch_log_group" "route53_resolver_queries" {
  name              = "/aws/route53resolver/query-logs"
  retention_in_days = 7 # Keep logs for 7 days (testing)

  tags = {
    Name    = "Route53-Resolver-Query-Logs"
    Purpose = "GuardDuty-DNS-Detection"
  }
}

# IAM Role for Route 53 Resolver to write to CloudWatch Logs
resource "aws_iam_role" "route53_resolver_logging" {
  name = "GuardDuty-Test-Route53-Resolver-Logging-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "route53resolver.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name    = "GuardDuty-Test-Route53-Resolver-Logging-Role"
    Project = "MSc-Dissertation"
  }
}

# IAM Policy for Route 53 Resolver to write logs
resource "aws_iam_role_policy" "route53_resolver_logging" {
  name = "Route53-Resolver-Logging-Policy"
  role = aws_iam_role.route53_resolver_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.route53_resolver_queries.arn}:*"
      }
    ]
  })
}

# Route 53 Resolver Query Log Config
resource "aws_route53_resolver_query_log_config" "guardduty_dns_logging" {
  name            = "guardduty-dns-query-logs"
  destination_arn = aws_cloudwatch_log_group.route53_resolver_queries.arn

  tags = {
    Name    = "GuardDuty-DNS-Query-Logs"
    Purpose = "GuardDuty-DNS-Detection"
  }
}

# Associate Route 53 Resolver Query Log Config with VPC
resource "aws_route53_resolver_query_log_config_association" "vpc_association" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.guardduty_dns_logging.id
  resource_id                  = aws_vpc.guardduty_test_vpc.id
}

