# Setup and Execution Guide

This document describes the procedure to deploy the experimental environment, enable relevant AWS telemetry, execute test activity, and collect evidence suitable for academic reporting.

## Prerequisites

- AWS account with permissions to create VPC/EC2/IAM/CloudWatch resources and to enable GuardDuty.
- Local tooling:
  - Terraform (v1.5 or later)
  - AWS CLI (configured)
  - Git
  - Python (for the local testing framework, if used)

## 1. Deploy the experimental environment (Terraform)

1. Determine the public IP range permitted to access the target.
2. Edit `terraform_code/variables.tf` and set `my_ip_cidr`.
3. Deploy:

```bash
cd terraform_code
terraform init
terraform plan
terraform apply
```

4. Record the outputs (public IP / URL and instance identifiers).

## 2. Verify target service availability

1. Wait for the instance bootstrap process to complete.
2. Confirm the web application is reachable:

```bash
curl -I http://<JUICE_SHOP_IP>
```

## 3. Enable and configure GuardDuty

1. Enable GuardDuty in the AWS Console for the selected region.
2. Confirm that relevant data sources are enabled (Flow Logs / DNS / CloudTrail) for the detector.
3. Set finding publishing frequency to a test-appropriate value (e.g., 15 minutes) to reduce reporting latency.

## 4. Execute test activity

Two approaches are supported:

- **A. Custom framework**: run the Python orchestration and monitoring scripts in `python_framework/` against the deployed target.
- **B. AWS GuardDuty Tester**: execute the AWS Labs test scenarios (if included as a dependency in this repository).

The dissertation should state explicitly which approach was used for each test series.

## 5. Evidence collection

Collect evidence for each test run, including:

- GuardDuty findings exported (JSON/CSV) for the relevant time window.
- Local execution logs produced by the selected test approach.
- Screenshots of configuration state and any findings as required by the dissertation narrative.

## 6. Cleanup

Destroy infrastructure resources when testing is complete:

```bash
cd terraform_code
terraform destroy
```
