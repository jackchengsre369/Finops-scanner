#!/usr/bin/env python3
"""
scan_unattached_volumes_gov.py

Find unattached EBS volumes across multiple AWS GovCloud accounts and all enabled regions.
Unattached EBS volumes have State == available.
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
    p = argparse.ArgumentParser(description="Scan AWS GovCloud accounts for unattached EBS volumes.")
    p.add_argument("--accounts-file", required=True, help="CSV, JSON, or TXT account list.")
    p.add_argument("--role-name", default=None, help="Role name to assume in each account.")
    p.add_argument("--role-arn-format", default="arn:aws-us-gov:iam::{account_id}:role/{role_name}")
    p.add_argument("--sts-region", default="us-gov-west-1")
    p.add_argument("--profile", default=None)
    p.add_argument("--output-csv", default="unattached_volumes.csv")
    p.add_argument("--output-json", default="unattached_volumes.json")
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
    args = {"RoleArn": role_arn, "RoleSessionName": f"scan-unattached-ebs-{account['account_id']}"}
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


def scan_region(session, account, region):
    ec2 = session.client("ec2", region_name=region)
    rows = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for v in page.get("Volumes", []):
            tags = v.get("Tags", [])
            rows.append({
                "account_id": account["account_id"],
                "account_name": account.get("account_name", ""),
                "region": region,
                "volume_id": v.get("VolumeId", ""),
                "availability_zone": v.get("AvailabilityZone", ""),
                "size_gib": v.get("Size", 0),
                "volume_type": v.get("VolumeType", ""),
                "state": v.get("State", ""),
                "encrypted": v.get("Encrypted", False),
                "kms_key_id": v.get("KmsKeyId", ""),
                "snapshot_id": v.get("SnapshotId", ""),
                "iops": v.get("Iops", ""),
                "throughput": v.get("Throughput", ""),
                "create_time": v.get("CreateTime").isoformat() if v.get("CreateTime") else "",
                "name_tag": tag_value(tags, "Name"),
                "all_tags": json.dumps(tags, default=str),
            })
    return rows


def write_csv(path, rows):
    fields = ["account_id", "account_name", "region", "volume_id", "availability_zone", "size_gib", "volume_type", "state", "encrypted", "kms_key_id", "snapshot_id", "iops", "throughput", "create_time", "name_tag", "all_tags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_json(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "total_unattached_volumes": len(rows), "total_unattached_gib": sum(int(r.get("size_gib") or 0) for r in rows), "volumes": rows}, f, indent=2, default=str)


def summarize(rows):
    print("\n===== Unattached EBS Volume Summary =====")
    if not rows:
        print("No unattached volumes found.")
        return
    summary = {}
    for r in rows:
        key = (r["account_id"], r.get("account_name", ""), r["region"])
        summary.setdefault(key, {"count": 0, "gib": 0})
        summary[key]["count"] += 1
        summary[key]["gib"] += int(r.get("size_gib") or 0)
    for (aid, name, region), d in sorted(summary.items()):
        label = f"{name} " if name else ""
        print(f"{label}{aid} | {region}: {d['count']} volumes, {d['gib']} GiB")


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
                print(f"[INFO] Scanning account={account['account_id']} region={region}")
                rows = scan_region(session, account, region)
                print(f"[INFO] Found {len(rows)} unattached volumes")
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
