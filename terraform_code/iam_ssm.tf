# IAM Role for EC2 to use Systems Manager (SSM)
resource "aws_iam_role" "ec2_ssm_role" {
  name = "GuardDuty-Test-EC2-SSM-Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "EC2-SSM-Role"
    Project = "MSc-Dissertation"
  }
}

# Attach AWS managed policy for SSM
resource "aws_iam_role_policy_attachment" "ssm_managed_instance_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Create instance profile
resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "GuardDuty-Test-EC2-SSM-Profile"
  role = aws_iam_role.ec2_ssm_role.name

  tags = {
    Name    = "EC2-SSM-Profile"
    Project = "MSc-Dissertation"
  }
}

