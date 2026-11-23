# TFPlan Lens

Offline cloud-security learning lab. Selected checks against Terraform plan JSON, not HCL text, state inspection or a complete policy engine. Initial code was AI-assisted.

## Run

Python 3.9+ is the intended compatibility target, not a personal testing claim.

```sh
python tfplan_lens.py examples/fictional-plan.json
python -m unittest discover -s tests -v
```

The fictional example should return 1 for public SSH. Exit 0 means no findings within this narrow scope, not secure infrastructure. Exit 1 includes findings requiring review. Exit 2 means input error.

For an existing saved plan, `terraform show -json saved.tfplan > plan.json` produces the input. This lab does not run Terraform, create a plan or apply changes. Terraform JSON can contain sensitive values in plain text. Keep actual plans private, outside this repository. Reports include resource addresses, which can also be sensitive. Only fictional data is included.

## Checks

- Inline aws_security_group ingress: public IPv4/IPv6 /0 access to SSH/RDP, or all protocols.
- aws_s3_bucket_public_access_block: explicitly disabled block settings.
- aws_db_instance: explicitly enabled public accessibility or disabled storage encryption.
- Unknown or missing selected planned values: manual-review findings, not a pass.

Deletion-only and data resources are skipped. Counts show reviewed and skipped resources. Only resource_changes with supported format major 1 are accepted. Provider schema changes can break assumptions.

## Limits

No cloud calls, graph evaluation, variable resolution, policy execution or live exposure test. Separate security-group rule resources, network ACLs, load balancers, non-/0 public ranges, account/org-level S3 controls, other resource types and provider-specific defaults are not evaluated. A bucket-level setting does not by itself prove a bucket is public. A publicly-accessible DB setting does not prove internet reachability. Unknown-value review is deliberately conservative. No claim is made that Dahoba has personally run or reviewed the code.

Read GUIDE_AR.md and explain these limits before presenting the project.

References:
- https://developer.hashicorp.com/terraform/internals/json-format
- https://developer.hashicorp.com/terraform/cli/commands/show

AWS rule context:
- https://docs.aws.amazon.com/config/latest/developerguide/vpc-sg-port-restriction-check.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/infrastructure-security.html
