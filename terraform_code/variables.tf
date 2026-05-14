# Terraform Variables
# Configure these before deploying

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "eu-west-2"  # London
}

variable "my_ip_cidr" {
  description = "Your public IP address in CIDR notation (e.g., 203.0.113.45/32)"
  type        = string
  # IMPORTANT: Change this to YOUR actual IP address
  # Find it by visiting: https://whatismyipaddress.com
  # Then add /32 at the end (e.g., "198.51.100.42/32")
  default     = "102.90.98.133/32"  # Sampson's IP
}

variable "ubuntu_ami" {
  description = "Ubuntu 22.04 LTS AMI ID for eu-west-2"
  type        = string
  # AMI for Ubuntu 22.04 LTS in eu-west-2 (verify current AMI)
  default     = "ami-0b9932f4918a00c4f"
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "MSc-GuardDuty-Research"
}
