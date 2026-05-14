# Terraform Outputs
# Important information displayed after deployment

output "juice_shop_public_ip" {
  description = "Public IP address of Juice Shop EC2 instance"
  value       = aws_eip.juice_shop_eip.public_ip
}

output "juice_shop_url" {
  description = "URL to access OWASP Juice Shop"
  value       = "http://${aws_eip.juice_shop_eip.public_ip}"
}

output "ec2_instance_id" {
  description = "EC2 Instance ID"
  value       = aws_instance.juice_shop_instance.id
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.guardduty_test_vpc.id
}

output "security_group_id" {
  description = "Security Group ID for web application"
  value       = aws_security_group.sg_web_app.id
}

output "ssh_command" {
  description = "SSH command to connect to EC2 instance"
  value       = "ssh -i your-key.pem ubuntu@${aws_eip.juice_shop_eip.public_ip}"
}

output "route53_resolver_query_log_config_id" {
  description = "Route 53 Resolver Query Log Config ID (for GuardDuty DNS detection)"
  value       = aws_route53_resolver_query_log_config.guardduty_dns_logging.id
}

output "route53_resolver_log_group" {
  description = "CloudWatch Log Group for Route 53 Resolver queries"
  value       = aws_cloudwatch_log_group.route53_resolver_queries.name
}

output "next_steps" {
  description = "Next steps after deployment"
  value       = <<-EOT
    
    ═══════════════════════════════════════════════════════════
    DEPLOYMENT COMPLETE
    ═══════════════════════════════════════════════════════════
    
    1. Access Juice Shop: http://${aws_eip.juice_shop_eip.public_ip}
    
    2. Enable GuardDuty:
       - Go to AWS Console → GuardDuty
       - Click "Get Started" → "Enable GuardDuty"
       - Enable: Extended Threat Detection, RDS Protection, S3 Protection
       - Set Finding Publishing Frequency to 15 MINUTES (for testing)
    
    3. Configure CloudTrail (if not already enabled):
       - Go to AWS Console → CloudTrail
       - Create trail (if needed)
    
    4. Verify VPC Flow Logs:
       - Go to CloudWatch → Log Groups
       - Check for: /aws/vpc/flowlogs
    
    5. Verify Route 53 Resolver Query Logs:
       - Go to CloudWatch → Log Groups
       - Check for: /aws/route53resolver/query-logs
       - This is REQUIRED for GuardDuty DNS exfiltration detection
    
    6. Wait 15-20 minutes for Juice Shop to fully initialize
       - Wait 5-10 minutes for Route 53 Resolver logs to start flowing
    
    ═══════════════════════════════════════════════════════════
  EOT
}
