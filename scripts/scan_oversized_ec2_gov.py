#!/usr/bin/env python3
"""
scan_oversized_ec2_gov.py

Find likely oversized EC2 instances across multiple AWS GovCloud accounts and all enabled regions.

Primary method:
  - Reads EC2 instances.
  - Pulls CloudWatch utilization metrics for the lookback window.
  - Flags running instances with low CPU, low network, and low EBS byte activity.
  - Optionally includes stopped instances as cleanup candidates.

Optional:
  - --use-compute-optimizer adds AWS Compute Optimizer findings/recommendations when available and enabled.

This scanner does not change resources. It only writes CSV/JSON reports.
"""

import argparse
import boto3
import botocore
import csv
import json
import os
import sys
from datetime import datetime, timedelta, timezone

DEFAULT_GOV_REGIONS = ["us-gov-west-1", "us-gov-east-1"]
METRIC_PERIOD_SECONDS = 86400
BYTES_PER_MIB = 1024 * 1024


def parse_args():
    p = argparse.ArgumentParser(description="Find likely oversized EC2 instances in AWS GovCloud.")
    p.add_argument("--accounts-file", required=True)
    p.add_argument("--role-name", default=None)
    p.add_argument("--role-arn-format", default="arn:aws-us-gov:iam::{account_id}:role/{role_name}")
    p.add_argument("--sts-region", default="us-gov-west-1")
    p.add_argument("--profile", default=None)
    p.add_argument("--lookback-days", type=int, default=14)
    p.add_argument("--cpu-avg-threshold", type=float, default=10.0)
    p.add_argument("--cpu-max-threshold", type=float, default=40.0)
    p.add_argument("--network-mib-per-day-threshold", type=float, default=100.0)
    p.add_argument("--ebs-mib-per-day-threshold", type=float, default=100.0)
    p.add_argument("--include-stopped", action="store_true")
    p.add_argument("--use-compute-optimizer", action="store_true")
    p.add_argument("--output-csv", default="oversized_ec2_instances.csv")
    p.add_argument("--output-json", default="oversized_ec2_instances.json")
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
    args = {"RoleArn": role_arn, "RoleSessionName": f"scan-oversized-ec2-{account['account_id']}"}
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


def list_instances(session, region):
    ec2 = session.client("ec2", region_name=region)
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instances.append(instance)
    return instances


def get_metric(cw, instance_id, metric_name, start, end, statistic):
    try:
        resp = cw.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName=metric_name,
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start,
            EndTime=end,
            Period=METRIC_PERIOD_SECONDS,
            Statistics=[statistic],
        )
        values = [float(dp[statistic]) for dp in resp.get("Datapoints", []) if statistic in dp]
        if not values:
            return None
        if statistic == "Average":
            return sum(values) / len(values)
        if statistic == "Maximum":
            return max(values)
        if statistic == "Sum":
            return sum(values)
        return None
    except botocore.exceptions.ClientError as e:
        print(f"[WARN] Metric failed for {instance_id} {metric_name}: {e}", file=sys.stderr)
        return None


def get_metrics(session, region, instance_id, lookback_days):
    cw = session.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    cpu_avg = get_metric(cw, instance_id, "CPUUtilization", start, end, "Average")
    cpu_max = get_metric(cw, instance_id, "CPUUtilization", start, end, "Maximum")
    net_in = get_metric(cw, instance_id, "NetworkIn", start, end, "Sum") or 0.0
    net_out = get_metric(cw, instance_id, "NetworkOut", start, end, "Sum") or 0.0
    ebs_read = get_metric(cw, instance_id, "EBSReadBytes", start, end, "Sum") or 0.0
    ebs_write = get_metric(cw, instance_id, "EBSWriteBytes", start, end, "Sum") or 0.0
    days = max(1, lookback_days)
    return {
        "has_cpu_metrics": cpu_avg is not None and cpu_max is not None,
        "cpu_avg_pct": round(cpu_avg, 2) if cpu_avg is not None else "",
        "cpu_max_pct": round(cpu_max, 2) if cpu_max is not None else "",
        "network_mib_per_day": round((net_in + net_out) / BYTES_PER_MIB / days, 2),
        "ebs_mib_per_day": round((ebs_read + ebs_write) / BYTES_PER_MIB / days, 2),
    }


def get_compute_optimizer_map(session, region):
    data = {}
    try:
        co = session.client("compute-optimizer", region_name=region)
        paginator = co.get_paginator("get_ec2_instance_recommendations")
        for page in paginator.paginate():
            for rec in page.get("instanceRecommendations", []):
                arn = rec.get("instanceArn", "")
                instance_id = arn.rsplit("/", 1)[-1]
                options = rec.get("recommendationOptions", [])
                top = options[0] if options else {}
                data[instance_id] = {
                    "compute_optimizer_finding": rec.get("finding", ""),
                    "compute_optimizer_recommended_type": top.get("instanceType", ""),
                    "compute_optimizer_savings_opportunity_pct": top.get("savingsOpportunity", {}).get("savingsOpportunityPercentage", ""),
                }
    except Exception as e:
        print(f"[WARN] Compute Optimizer unavailable or disabled in {region}: {e}", file=sys.stderr)
    return data


def low_utilization(metrics, args):
    if not metrics["has_cpu_metrics"]:
        return False
    return (
        metrics["cpu_avg_pct"] <= args.cpu_avg_threshold
        and metrics["cpu_max_pct"] <= args.cpu_max_threshold
        and metrics["network_mib_per_day"] <= args.network_mib_per_day_threshold
        and metrics["ebs_mib_per_day"] <= args.ebs_mib_per_day_threshold
    )


def recommendation_reason(state, metrics, args):
    if state == "stopped":
        return "Instance is stopped. Validate owner/business need; consider termination if unused."
    if not metrics["has_cpu_metrics"]:
        return "No CloudWatch CPU metrics found in lookback window. Validate monitoring before downsizing."
    return (
        f"Low utilization over {args.lookback_days} days: avg CPU <= {args.cpu_avg_threshold}%, "
        f"max CPU <= {args.cpu_max_threshold}%, network <= {args.network_mib_per_day_threshold} MiB/day, "
        f"EBS <= {args.ebs_mib_per_day_threshold} MiB/day. Review for downsize, scheduling, stop, or terminate."
    )


def scan_region(session, account, region, args):
    rows = []
    optimizer = get_compute_optimizer_map(session, region) if args.use_compute_optimizer else {}
    for i in list_instances(session, region):
        state = i.get("State", {}).get("Name", "")
        if state == "terminated":
            continue
        if state == "stopped" and not args.include_stopped:
            continue

        instance_id = i.get("InstanceId", "")
        metrics = {"has_cpu_metrics": False, "cpu_avg_pct": "", "cpu_max_pct": "", "network_mib_per_day": "", "ebs_mib_per_day": ""}
        candidate_type = ""

        if state == "running":
            metrics = get_metrics(session, region, instance_id, args.lookback_days)
            if low_utilization(metrics, args):
                candidate_type = "oversized_low_utilization"
        elif state == "stopped":
            candidate_type = "stopped_cleanup_candidate"

        co = optimizer.get(instance_id, {})
        if co.get("compute_optimizer_finding") == "OVER_PROVISIONED":
            candidate_type = candidate_type or "compute_optimizer_overprovisioned"

        if not candidate_type:
            continue

        tags = i.get("Tags", [])
        rows.append({
            "account_id": account["account_id"],
            "account_name": account.get("account_name", ""),
            "region": region,
            "instance_id": instance_id,
            "instance_type": i.get("InstanceType", ""),
            "state": state,
            "candidate_type": candidate_type,
            "name_tag": tag_value(tags, "Name"),
            "platform": i.get("PlatformDetails", ""),
            "launch_time": i.get("LaunchTime").isoformat() if i.get("LaunchTime") else "",
            "availability_zone": i.get("Placement", {}).get("AvailabilityZone", ""),
            "private_ip": i.get("PrivateIpAddress", ""),
            "cpu_avg_pct": metrics["cpu_avg_pct"],
            "cpu_max_pct": metrics["cpu_max_pct"],
            "network_mib_per_day": metrics["network_mib_per_day"],
            "ebs_mib_per_day": metrics["ebs_mib_per_day"],
            "lookback_days": args.lookback_days,
            "compute_optimizer_finding": co.get("compute_optimizer_finding", ""),
            "compute_optimizer_recommended_type": co.get("compute_optimizer_recommended_type", ""),
            "compute_optimizer_savings_opportunity_pct": co.get("compute_optimizer_savings_opportunity_pct", ""),
            "recommendation": recommendation_reason(state, metrics, args),
            "all_tags": json.dumps(tags, default=str),
        })
    return rows


def write_csv(path, rows):
    fields = ["account_id", "account_name", "region", "instance_id", "instance_type", "state", "candidate_type", "name_tag", "platform", "launch_time", "availability_zone", "private_ip", "cpu_avg_pct", "cpu_max_pct", "network_mib_per_day", "ebs_mib_per_day", "lookback_days", "compute_optimizer_finding", "compute_optimizer_recommended_type", "compute_optimizer_savings_opportunity_pct", "recommendation", "all_tags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_json(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "total_candidates": len(rows), "instances": rows}, f, indent=2, default=str)


def summarize(rows):
    print("\n===== Oversized EC2 Summary =====")
    if not rows:
        print("No candidates found.")
        return
    summary = {}
    for r in rows:
        key = (r["account_id"], r.get("account_name", ""), r["region"], r["candidate_type"])
        summary[key] = summary.get(key, 0) + 1
    for (aid, name, region, ctype), count in sorted(summary.items()):
        label = f"{name} " if name else ""
        print(f"{label}{aid} | {region} | {ctype}: {count}")


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
                print(f"[INFO] Scanning EC2 account={account['account_id']} region={region}")
                rows = scan_region(session, account, region, args)
                print(f"[INFO] Found {len(rows)} EC2 candidates")
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
