"""Narrow offline checks for selected AWS resources in Terraform plan JSON."""
import argparse
import ipaddress
import json


def public_network(value):
    try:
        return ipaddress.ip_network(value, strict=False).prefixlen == 0
    except (TypeError, ValueError):
        return False


def scan(plan):
    if not isinstance(plan, dict) or str(plan.get('format_version', '')).split('.')[0] != '1':
        raise ValueError('Expected supported Terraform plan JSON format 1.x')
    changes = plan.get('resource_changes')
    if not isinstance(changes, list):
        raise ValueError('Expected resource_changes list; state JSON is not a plan')
    findings = []; reviewed = 0; skipped = 0
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get('change'), dict):
            raise ValueError('Malformed resource change')
        change = item['change']
        if not isinstance(change.get('actions'), list):
            raise ValueError('Expected resource action list')
        if change.get('actions') == ['delete'] or item.get('mode', 'managed') != 'managed':
            skipped += 1; continue
        kind = item.get('type'); after = change.get('after')
        if kind not in {'aws_security_group', 'aws_s3_bucket_public_access_block', 'aws_db_instance'}:
            skipped += 1; continue
        reviewed += 1
        address = item.get('address', '<unknown-address>')
        def add(rule, severity, message):
            findings.append({'address': address, 'rule': rule, 'severity': severity, 'message': message})
        if change.get('after_unknown'):
            add('REVIEW_UNKNOWN', 'review', 'Unknown planned attributes require manual review')
        if not isinstance(after, dict):
            add('REVIEW_MISSING', 'review', 'Planned values are unavailable'); continue
        if kind == 'aws_security_group':
            ingress = after.get('ingress')
            if not isinstance(ingress, list):
                add('REVIEW_INGRESS', 'review', 'Inline ingress unavailable'); continue
            for rule in ingress:
                if not isinstance(rule, dict):
                    add('REVIEW_INGRESS', 'review', 'Malformed inline ingress'); continue
                ipv4, ipv6 = rule.get('cidr_blocks', []), rule.get('ipv6_cidr_blocks', [])
                if not isinstance(ipv4, list) or not isinstance(ipv6, list):
                    raise ValueError('Expected CIDR lists')
                cidrs = ipv4 + ipv6
                if not all(isinstance(cidr, str) for cidr in cidrs):
                    raise ValueError('Expected CIDR strings')
                for cidr in cidrs:
                    try:
                        ipaddress.ip_network(cidr, strict=False)
                    except ValueError as error:
                        raise ValueError('Invalid CIDR in inline ingress') from error
                if not any(public_network(c) for c in cidrs): continue
                protocol = str(rule.get('protocol', '')).lower()
                lo, hi = rule.get('from_port'), rule.get('to_port')
                if protocol == '-1' or (protocol in {'tcp', '6'} and type(lo) is int
                        and type(hi) is int and any(lo <= port <= hi for port in (22, 3389))):
                    add('SG_PUBLIC_ADMIN', 'high', 'Inline rule permits public SSH/RDP or all protocols')
        elif kind == 'aws_s3_bucket_public_access_block':
            keys = ('block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets')
            if any(after.get(key) is False for key in keys):
                add('S3_BLOCK_DISABLED', 'medium', 'A bucket-level public-access block setting is disabled')
            if any(key not in after or after[key] is None for key in keys):
                add('REVIEW_S3_BLOCK', 'review', 'A public-access block setting is unavailable')
        elif kind == 'aws_db_instance':
            if after.get('publicly_accessible') is True:
                add('DB_PUBLIC', 'high', 'DB instance requests public accessibility')
            if after.get('storage_encrypted') is False:
                add('DB_UNENCRYPTED', 'high', 'DB instance explicitly disables storage encryption')
            if any(key not in after or after[key] is None for key in ('publicly_accessible', 'storage_encrypted')):
                add('REVIEW_DB', 'review', 'DB security attributes are unavailable')
    return {'reviewed_resources': reviewed, 'skipped_resources': skipped, 'findings': findings,
            'scope': 'Selected planned resources only. No findings is not a secure verdict.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('plan')
    args = parser.parse_args(argv)
    try:
        with open(args.plan, encoding='utf-8') as f: result = scan(json.load(f))
        print(json.dumps(result, indent=2))
        return 1 if result['findings'] else 0
    except (OSError, ValueError, TypeError) as error:
        parser.exit(2, f'Input error: {error}\n')


if __name__ == '__main__': raise SystemExit(main())
