from datetime import datetime, timezone
import uuid


def collect_iam_roles(iam_client):
    result = []

    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            result.append({
                "name": role["RoleName"],
                "arn": role["Arn"],
                "is_irsa": False,
                "irsa_oidc_issuer": None,
                "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                "attached_policies": [],
                "inline_policies": [],
            })

    return result


def collect_iam_users(iam_client):
    result = []

    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            access_keys = iam_client.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            active_keys = [k for k in access_keys if k["Status"] == "Active"]

            # 최소 버전: active key 있는 사용자만 의미 있는 대상으로 수집
            if not active_keys:
                continue

            mfa_devices = iam_client.list_mfa_devices(UserName=user["UserName"])["MFADevices"]

            result.append({
                "username": user["UserName"],
                "arn": user["Arn"],
                "access_keys": [
                    {
                        "access_key_id": k["AccessKeyId"],
                        "status": k["Status"],
                        "create_date": k["CreateDate"].isoformat(),
                    }
                    for k in access_keys
                ],
                "attached_policies": [],
                "inline_policies": [],
                "has_mfa": len(mfa_devices) > 0,
                "last_used": None,
            })

    return result


def collect_s3_buckets(s3_client):
    result = []

    response = s3_client.list_buckets()
    for bucket in response.get("Buckets", []):
        name = bucket["Name"]
        result.append({
            "name": name,
            "arn": f"arn:aws:s3:::{name}",
            "public_access_block": None,
            "encryption": None,
            "versioning": "Unknown",
            "logging_enabled": False,
        })

    return result


def collect_rds_instances(rds_client):
    result = []

    paginator = rds_client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            result.append({
                "identifier": db["DBInstanceIdentifier"],
                "arn": db["DBInstanceArn"],
                "engine": db["Engine"],
                "engine_version": db["EngineVersion"],
                "storage_encrypted": db["StorageEncrypted"],
                "publicly_accessible": db["PubliclyAccessible"],
                "vpc_security_groups": [
                    sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])
                ],
            })

    return result


def collect_ec2_instances(ec2_client):
    result = []

    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                result.append({
                    "instance_id": inst["InstanceId"],
                    "private_ip": inst.get("PrivateIpAddress"),
                    "iam_instance_profile": inst.get("IamInstanceProfile"),
                    "metadata_options": inst.get("MetadataOptions", {}),
                    "security_groups": [
                        sg["GroupId"] for sg in inst.get("SecurityGroups", [])
                    ],
                })

    return result


def collect_all_assets(session, account_id: str, region: str):
    iam = session.client("iam")
    s3 = session.client("s3", region_name=region)
    rds = session.client("rds", region_name=region)
    ec2 = session.client("ec2", region_name=region)

    return {
        "scan_id": f"scan-{uuid.uuid4()}",
        "aws_account_id": account_id,
        "region": region,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "iam_roles": collect_iam_roles(iam),
        "iam_users": collect_iam_users(iam),
        "s3_buckets": collect_s3_buckets(s3),
        "rds_instances": collect_rds_instances(rds),
        "ec2_instances": collect_ec2_instances(ec2),
        "security_groups": [],
    }