#!/bin/bash
# Apply SSM configuration to existing infrastructure

echo "=========================================="
echo "Adding SSM Support to EC2 Instance"
echo "=========================================="

# Initialize Terraform (in case of new files)
terraform init

# Validate configuration
echo -e "\nValidating Terraform configuration..."
terraform validate

if [ $? -ne 0 ]; then
    echo "Terraform validation failed!"
    exit 1
fi

# Show what will change
echo -e "\nPreviewing changes..."
terraform plan

echo -e "\n=========================================="
echo "Apply these changes? (yes/no)"
read -r response

if [ "$response" = "yes" ]; then
    echo -e "\nApplying SSM configuration..."
    terraform apply
    
    echo -e "\n=========================================="
    echo "SSM configuration applied successfully!"
    echo ""
    echo "Your EC2 instance now has:"
    echo "  - IAM role: GuardDuty-Test-EC2-SSM-Role"
    echo "  - SSM permissions enabled"
    echo "  - Ready for DNS exfiltration tests!"
    echo "=========================================="
else
    echo "Cancelled by user"
fi
