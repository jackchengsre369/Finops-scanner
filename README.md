# FinOps Scanner

Python scanners for AWS GovCloud FinOps cleanup and EBS optimization reporting.

## Included scripts

- `scripts/scan_gp2_to_gp3_savings_gov.py` — finds all gp2 EBS volumes across GovCloud accounts and regions, then estimates gp3 migration savings.
- `scripts/scan_orphaned_snapshots_gov.py` — finds orphaned / cleanup-candidate EBS snapshots across GovCloud accounts and regions.

## Example accounts.csv

```csv
account_id,account_name
123456789012,gov-dev
234567890123,gov-prod
```

Optional role ARN and external ID:

```csv
account_id,account_name,role_arn,external_id
123456789012,gov-dev,arn:aws-us-gov:iam::123456789012:role/FinOpsReadOnlyRole,my-external-id
```

## Run gp2 to gp3 savings scanner

```bash
python scripts/scan_gp2_to_gp3_savings_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --output-csv gp2_to_gp3_savings.csv \
  --output-json gp2_to_gp3_savings.json
```

Use CUR-derived prices for a no-dispute report:

```bash
python scripts/scan_gp2_to_gp3_savings_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --gp2-gb-month 0.120 \
  --gp3-gb-month 0.096 \
  --gp3-iops-month-over-3000 0.006 \
  --gp3-throughput-month-over-125 0.048
```

## Run orphaned snapshot scanner

```bash
python scripts/scan_orphaned_snapshots_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --min-age-days 30 \
  --output-csv orphaned_snapshots.csv \
  --output-json orphaned_snapshots.json
```

Optional upper-bound snapshot estimate:

```bash
python scripts/scan_orphaned_snapshots_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --min-age-days 30 \
  --snapshot-price-per-gb-month 0.06
```

## IAM permissions

The assumed role in each GovCloud account needs read-only EC2 permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeImages"
      ],
      "Resource": "*"
    }
  ]
}
```

The source identity, such as a GitLab Runner role, needs `sts:AssumeRole` into each target GovCloud account role.
