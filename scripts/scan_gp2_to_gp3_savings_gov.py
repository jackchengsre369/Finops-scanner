#!/usr/bin/env python3
"""
scan_gp2_to_gp3_savings_gov.py

Find gp2 EBS volumes across AWS GovCloud accounts and estimate savings from moving to gp3.
Uses pagination and assumes a role into each account.

Savings outputs:
  1. baseline_gp3: gp3 storage only using included 3,000 IOPS and 125 MiB/s throughput.
  2. preserve_perf_gp3: gp3 sized to preserve estimated gp2 baseline IOPS and throughput.

For no-dispute reporting, override prices with CUR-derived GovCloud rates.
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
    p = argparse.ArgumentParser(description="Find gp2 EBS volumes and estimate gp3 migration savings in AWS GovCloud.")
    p.add_argument("--accounts-file", required=True)
    p.add_argument("--role-name", default=None)
    p.add_argument("--role-arn-format", default="arn:aws-us-gov:iam::{account_id}:role/{role_name}")
    p.add_argument("--sts-region", default="us-gov-west-1")
    p.add_argument("--profile", default=None)
    p.add_argument("--gp2-gb-month", type=float, default=0.120, help="gp2 $/GB-month. Override with CUR rate.")
    p.add_argument("--gp3-gb-month", type=float, default=0.096, help="gp3 $/GB-month. Override with CUR rate.")
    p.add_argument("--gp3-iops-month-over-3000", type=float, default=0.006, help="gp3 $/provisioned IOPS-month above 3000.")
    p.add_argument("--gp3-throughput-month-over-125", type=float, default=0.048, help="gp3 $/MiB/s-month above 125.")
    p.add_argument("--output-csv", default="gp2_to_gp3_savings.csv")
    p.add_argument("--output-json", default="gp2_to_gp3_savings.json")
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
    args = {"RoleArn": role_arn, "RoleSessionName": f"scan-gp2-gp3-{account['account_id']}"}
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


def estimate_gp2_iops(size_gib):
    return min(16000, max(100, int(size_gib) * 3))


def estimate_gp2_throughput_mibps(size_gib):
    # Conservative baseline estimate for reporting. gp2 throughput can burst; large volumes are capped around 250 MiB/s.
    return min(250, max(128, int(int(size_gib) * 0.25)))


def price_gp3(size_gib, iops, throughput, args):
    storage = size_gib * args.gp3_gb_month
    iops_extra = max(0, int(iops) - 3000) * args.gp3_iops_month_over_3000
    throughput_extra = max(0, int(throughput) - 125) * args.gp3_throughput_month_over_125
    return round(storage + iops_extra + throughput_extra, 2)


def scan_region(session, account, region, args):
    ec2 = session.client("ec2", region_name=region)
    rows = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "volume-type", "Values": ["gp2"]}]):
        for v in page.get("Volumes", []):
            size = int(v.get("Size", 0))
            gp2_cost = round(size * args.gp2_gb_month, 2)
            gp3_baseline_cost = round(size * args.gp3_gb_month, 2)
            gp2_iops = estimate_gp2_iops(size)
            gp2_throughput = estimate_gp2_throughput_mibps(size)
            gp3_preserve_cost = price_gp3(size, gp2_iops, gp2_throughput, args)
            tags = v.get("Tags", [])
            rows.append({
                "account_id": account["account_id"],
                "account_name": account.get("account_name", ""),
                "region": region,
                "volume_id": v.get("VolumeId", ""),
                "availability_zone": v.get("AvailabilityZone", ""),
                "state": v.get("State", ""),
                "size_gib": size,
                "current_type": "gp2",
                "recommended_type": "gp3",
                "estimated_gp2_iops": gp2_iops,
                "estimated_gp2_throughput_mibps": gp2_throughput,
                "gp2_monthly_cost": gp2_cost,
                "gp3_baseline_monthly_cost": gp3_baseline_cost,
                "gp3_preserve_perf_monthly_cost": gp3_preserve_cost,
                "baseline_monthly_savings": round(gp2_cost - gp3_baseline_cost, 2),
                "preserve_perf_monthly_savings": round(gp2_cost - gp3_preserve_cost, 2),
                "encrypted": v.get("Encrypted", False),
                "kms_key_id": v.get("KmsKeyId", ""),
                "snapshot_id": v.get("SnapshotId", ""),
                "create_time": v.get("CreateTime").isoformat() if v.get("CreateTime") else "",
                "name_tag": tag_value(tags, "Name"),
                "all_tags": json.dumps(tags, default=str),
            })
    return rows


def write_csv(path, rows):
    fields = ["account_id", "account_name", "region", "volume_id", "availability_zone", "state", "size_gib", "current_type", "recommended_type", "estimated_gp2_iops", "estimated_gp2_throughput_mibps", "gp2_monthly_cost", "gp3_baseline_monthly_cost", "gp3_preserve_perf_monthly_cost", "baseline_monthly_savings", "preserve_perf_monthly_savings", "encrypted", "kms_key_id", "snapshot_id", "create_time", "name_tag", "all_tags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_json(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "total_gp2_volumes": len(rows), "total_size_gib": sum(int(r.get("size_gib") or 0) for r in rows), "baseline_monthly_savings": round(sum(float(r.get("baseline_monthly_savings") or 0) for r in rows), 2), "preserve_perf_monthly_savings": round(sum(float(r.get("preserve_perf_monthly_savings") or 0) for r in rows), 2), "volumes": rows}, f, indent=2, default=str)


def summarize(rows):
    print("\n===== gp2 to gp3 Savings Summary =====")
    if not rows:
        print("No gp2 volumes found.")
        return
    summary = {}
    for r in rows:
        key = (r["account_id"], r.get("account_name", ""), r["region"])
        summary.setdefault(key, {"count": 0, "gib": 0, "baseline": 0.0, "preserve": 0.0})
        summary[key]["count"] += 1
        summary[key]["gib"] += int(r["size_gib"])
        summary[key]["baseline"] += float(r["baseline_monthly_savings"])
        summary[key]["preserve"] += float(r["preserve_perf_monthly_savings"])
    for (aid, name, region), d in sorted(summary.items()):
        label = f"{name} " if name else ""
        print(f"{label}{aid} | {region}: {d['count']} gp2 volumes, {d['gib']} GiB, baseline savings ${d['baseline']:.2f}/mo, preserve-perf savings ${d['preserve']:.2f}/mo")


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
                print(f"[INFO] Scanning gp2 volumes account={account['account_id']} region={region}")
                rows = scan_region(session, account, region, args)
                print(f"[INFO] Found {len(rows)} gp2 volumes")
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
