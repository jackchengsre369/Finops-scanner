#!/usr/bin/env python3
"""
scan_orphaned_snapshots_gov.py

Find orphaned / cleanup-candidate EBS snapshots across multiple AWS GovCloud accounts
and all enabled regions.

Definition used by this report:
  - Snapshot is owned by the account.
  - Snapshot is not referenced by any AMI owned by the account.
  - Snapshot source VolumeId is missing or no longer exists in the region.
  - Optional --min-age-days can exclude newer snapshots.

Important: EBS snapshot storage is incremental. The size field is the source volume size,
not necessarily the actual billable snapshot storage. Use CUR to reconcile final savings.
"""

import argparse
import boto3
import botocore
import csv
import json
import os
import sys
from datetime import datetime, timezone

DEFAULT_GOV_REGIONS = ["us-gov-west-1", "us-gov-east-1"]


def parse_args():
    p = argparse.ArgumentParser(description="Find orphaned EBS snapshots in AWS GovCloud.")
    p.add_argument("--accounts-file", required=True)
    p.add_argument("--role-name", default=None)
    p.add_argument("--role-arn-format", default="arn:aws-us-gov:iam::{account_id}:role/{role_name}")
    p.add_argument("--sts-region", default="us-gov-west-1")
    p.add_argument("--profile", default=None)
    p.add_argument("--min-age-days", type=int, default=0, help="Only report snapshots older than this many days.")
    p.add_argument("--snapshot-price-per-gb-month", type=float, default=0.0, help="Optional upper-bound $/GB-month estimate. Use CUR-derived rate.")
    p.add_argument("--output-csv", default="orphaned_snapshots.csv")
    p.add_argument("--output-json", default="orphaned_snapshots.json")
    return p.parse_args()


def load_accounts(path):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [{"account_id": str(x.get("account_id", "")).strip(), "account_name": str(x.get("account_name", "")).strip(), "role_arn": str(x.get("role_arn", "")).strip(), "external_id": str(x.get("external_id", "")).strip()} for x in data]
    if ext == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            return [{"account_id": str(r.get("account_id", "")).strip(), "account_name": str(r.get("account_name", "")).strip(), "role_arn": str(r.get("role_arn", "")).strip(), "external_id": str(r.get("external_id", "")).strip()} for r in csv.DictReader(f)]
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [x.strip() for x in line.split(",")]
            rows.append({"account_id": parts[0], "account_name": parts[1] if len(parts) > 1 else "", "role_arn": parts[2] if len(parts) > 2 else "", "external_id": parts[3] if len(parts) > 3 else ""})
    return rows


def validate_account(account):
    aid = account["account_id"]
    if not aid.isdigit() or len(aid) != 12:
        raise ValueError(f"Invalid account_id: {aid}")


def assume_role(source_session, account, role_name, role_arn_format, sts_region):
    role_arn = account.get("role_arn") or ""
    if not role_arn:
        if not role_name:
            raise ValueError(f"No role_arn and no --role-name for {account['account_id']}")
        role_arn = role_arn_format.format(account_id=account["account_id"], role_name=role_name)
    args = {"RoleArn": role_arn, "RoleSessionName": f"scan-orphaned-snapshots-{account['account_id']}"}
    if account.get("external_id"):
        args["ExternalId"] = account["external_id"]
    creds = source_session.client("sts", region_name=sts_region).assume_role(**args)["Credentials"]
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"], region_name=sts_region)


def get_regions(session):
    try:
        ec2 = session.client("ec2", region_name="us-gov-west-1")
        regions = []
        for r in ec2.describe_regions(AllRegions=True).get("Regions", []):
            if r.get("OptInStatus", "opt-in-not-required") in ("opt-in-not-required", "opted-in"):
                regions.append(r["RegionName"])
        return sorted(set(regions)) or DEFAULT_GOV_REGIONS
    except botocore.exceptions.ClientError as e:
        print(f"[WARN] Region discovery failed: {e}", file=sys.stderr)
        return DEFAULT_GOV_REGIONS


def tag_value(tags, key):
    for t in tags or []:
        if t.get("Key") == key:
            return t.get("Value", "")
    return ""


def list_existing_volume_ids(ec2):
    ids = set()
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for v in page.get("Volumes", []):
            ids.add(v.get("VolumeId"))
    return ids


def list_ami_snapshot_ids(ec2):
    ami_snapshot_ids = set()
    paginator = ec2.get_paginator("describe_images")
    for page in paginator.paginate(Owners=["self"]):
        for image in page.get("Images", []):
            for mapping in image.get("BlockDeviceMappings", []):
                snap_id = mapping.get("Ebs", {}).get("SnapshotId")
                if snap_id:
                    ami_snapshot_ids.add(snap_id)
    return ami_snapshot_ids


def snapshot_age_days(start_time):
    if not start_time:
        return ""
    now = datetime.now(timezone.utc)
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
    return (now - start_time).days


def scan_region(session, account, region, args):
    ec2 = session.client("ec2", region_name=region)
    existing_volume_ids = list_existing_volume_ids(ec2)
    ami_snapshot_ids = list_ami_snapshot_ids(ec2)
    rows = []
    paginator = ec2.get_paginator("describe_snapshots")
    for page in paginator.paginate(OwnerIds=["self"]):
        for s in page.get("Snapshots", []):
            if s.get("State") != "completed":
                continue
            snap_id = s.get("SnapshotId", "")
            if snap_id in ami_snapshot_ids:
                continue
            start_time = s.get("StartTime")
            age = snapshot_age_days(start_time)
            if isinstance(age, int) and age < args.min_age_days:
                continue
            source_volume_id = s.get("VolumeId", "")
            volume_missing = not source_volume_id or source_volume_id not in existing_volume_ids
            if not volume_missing:
                continue
            volume_size = int(s.get("VolumeSize", 0) or 0)
            upper_bound_savings = round(volume_size * args.snapshot_price_per_gb_month, 2) if args.snapshot_price_per_gb_month else ""
            tags = s.get("Tags", [])
            reason = "source_volume_missing_or_deleted;not_referenced_by_owned_ami"
            rows.append({
                "account_id": account["account_id"],
                "account_name": account.get("account_name", ""),
                "region": region,
                "snapshot_id": snap_id,
                "source_volume_id": source_volume_id,
                "volume_size_gib_upper_bound": volume_size,
                "state": s.get("State", ""),
                "start_time": start_time.isoformat() if start_time else "",
                "age_days": age,
                "encrypted": s.get("Encrypted", False),
                "kms_key_id": s.get("KmsKeyId", ""),
                "storage_tier": s.get("StorageTier", "standard"),
                "description": s.get("Description", ""),
                "name_tag": tag_value(tags, "Name"),
                "cleanup_candidate_reason": reason,
                "estimated_monthly_savings_upper_bound": upper_bound_savings,
                "all_tags": json.dumps(tags, default=str),
            })
    return rows


def write_csv(path, rows):
    fields = ["account_id", "account_name", "region", "snapshot_id", "source_volume_id", "volume_size_gib_upper_bound", "state", "start_time", "age_days", "encrypted", "kms_key_id", "storage_tier", "description", "name_tag", "cleanup_candidate_reason", "estimated_monthly_savings_upper_bound", "all_tags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_json(path, rows):
    numeric_savings = [float(r["estimated_monthly_savings_upper_bound"]) for r in rows if r.get("estimated_monthly_savings_upper_bound") not in ("", None)]
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "total_orphaned_snapshots": len(rows), "total_volume_size_gib_upper_bound": sum(int(r.get("volume_size_gib_upper_bound") or 0) for r in rows), "estimated_monthly_savings_upper_bound": round(sum(numeric_savings), 2) if numeric_savings else "", "snapshots": rows}, f, indent=2, default=str)


def summarize(rows):
    print("\n===== Orphaned EBS Snapshot Summary =====")
    if not rows:
        print("No orphaned snapshots found.")
        return
    summary = {}
    for r in rows:
        key = (r["account_id"], r.get("account_name", ""), r["region"])
        summary.setdefault(key, {"count": 0, "gib": 0, "savings": 0.0})
        summary[key]["count"] += 1
        summary[key]["gib"] += int(r.get("volume_size_gib_upper_bound") or 0)
        if r.get("estimated_monthly_savings_upper_bound") not in ("", None):
            summary[key]["savings"] += float(r["estimated_monthly_savings_upper_bound"])
    for (aid, name, region), d in sorted(summary.items()):
        label = f"{name} " if name else ""
        savings = f", upper-bound savings ${d['savings']:.2f}/mo" if d["savings"] else ""
        print(f"{label}{aid} | {region}: {d['count']} snapshots, {d['gib']} GiB upper-bound{savings}")


def main():
    args = parse_args()
    source = boto3.Session(profile_name=args.profile, region_name=args.sts_region) if args.profile else boto3.Session(region_name=args.sts_region)
    all_rows = []
    for account in load_accounts(args.accounts_file):
        try:
            validate_account(account)
            print(f"\n[INFO] Assuming role for {account.get('account_name', '')} {account['account_id']}")
            session = assume_role(source, account, args.role_name, args.role_arn_format, args.sts_region)
            for region in get_regions(session):
                print(f"[INFO] Scanning snapshots account={account['account_id']} region={region}")
                rows = scan_region(session, account, region, args)
                print(f"[INFO] Found {len(rows)} orphaned snapshot candidates")
                all_rows.extend(rows)
        except Exception as e:
            print(f"[ERROR] Skipping account {account.get('account_id', '')}: {e}", file=sys.stderr)
    write_csv(args.output_csv, all_rows)
    write_json(args.output_json, all_rows)
    summarize(all_rows)
    print(f"\nCSV written to: {args.output_csv}")
    print(f"JSON written to: {args.output_json}")


if __name__ == "__main__":
    main()
