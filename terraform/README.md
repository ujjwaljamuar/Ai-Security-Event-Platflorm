# Terraform — Security Event Platform

## Region
ap-south-1 (Mumbai)

## Resources
- Kinesis Data Stream
- Producer IAM policy
- Consumer IAM policy

## State
Local state for the initial development setup.
Do not commit Terraform state files.

## Workflow
1. terraform init
2. terraform fmt -check
3. terraform validate
4. terraform plan -out=tfplan
5. Review the plan before applying.

Do not apply without explicit approval.