# FinOps Scanner

Python scanners for AWS GovCloud FinOps cleanup and EBS/EC2 optimization reporting.

## Included standalone scanners

1. `scripts/scan_unattached_volumes_gov.py`
   - Finds unattached EBS volumes where `State == available`.

2. `scripts/scan_gp2_to_gp3_savings_gov.py`
   - Finds gp2 EBS volumes and estimates monthly savings from moving to gp3.
   - Reports both baseline gp3 savings and performance-preserved gp3 savings.

3. `scripts/scan_orphaned_snapshots_gov.py`
   - Finds EBS snapshots whose source volume is missing/deleted.
   - Excludes snapshots still referenced by owned AMIs.

4. `scripts/scan_oversized_ec2_gov.py`
   - Finds likely oversized EC2 instances using CloudWatch utilization metrics.
   - Optional Compute Optimizer enrichment with `--use-compute-optimizer`.

## Example accounts.csv

```csv
account_id,account_name
123456789012,gov-dev
234567890123,gov-prod
```

Optional explicit role ARN and external ID:

```csv
account_id,account_name,role_arn,external_id
123456789012,gov-dev,arn:aws-us-gov:iam::123456789012:role/FinOpsReadOnlyRole,my-external-id
```

## 1. Run unattached EBS volume scanner

```bash
python scripts/scan_unattached_volumes_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --output-csv unattached_volumes.csv \
  --output-json unattached_volumes.json
```

## 2. Run gp2 to gp3 savings scanner

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

## 3. Run orphaned snapshot scanner

```bash
python scripts/scan_orphaned_snapshots_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --min-age-days 30 \
  --output-csv orphaned_snapshots.csv \
  --output-json orphaned_snapshots.json
```

Optional upper-bound snapshot estimate. Snapshot size is not the exact billable incremental storage, so reconcile final savings with CUR:

```bash
python scripts/scan_orphaned_snapshots_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --min-age-days 30 \
  --snapshot-price-per-gb-month 0.06
```

## 4. Run oversized EC2 scanner

Basic low-utilization scan:

```bash
python scripts/scan_oversized_ec2_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --lookback-days 14 \
  --cpu-avg-threshold 10 \
  --cpu-max-threshold 40 \
  --network-mib-per-day-threshold 100 \
  --ebs-mib-per-day-threshold 100 \
  --output-csv oversized_ec2_instances.csv \
  --output-json oversized_ec2_instances.json
```

Include stopped instances and AWS Compute Optimizer findings when available:

```bash
python scripts/scan_oversized_ec2_gov.py \
  --accounts-file accounts.csv \
  --role-name FinOpsReadOnlyRole \
  --lookback-days 14 \
  --include-stopped \
  --use-compute-optimizer
```

## Required IAM permissions

The assumed role in each GovCloud account needs read-only EC2 and CloudWatch permissions. Add Compute Optimizer permissions only if you run the oversized EC2 scanner with `--use-compute-optimizer`.

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
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "cloudwatch:GetMetricStatistics",
        "compute-optimizer:GetEC2InstanceRecommendations"
      ],
      "Resource": "*"
    }
  ]
}
```

The source identity, such as a GitLab Runner role, needs `sts:AssumeRole` into each target GovCloud account role.

## Notes for defensible savings reports

- Use CUR-derived rates as CLI overrides for EBS pricing.
- Treat orphaned snapshot savings as upper-bound unless reconciled with CUR because EBS snapshots are incremental.
- Treat oversized EC2 findings as review candidates, not automatic termination or resize decisions.
- EC2 memory utilization is not available in default CloudWatch metrics unless the CloudWatch Agent is installed.
