# Capstone Design Doc: Acme Health Patient Intake API

This is my working design doc for the CGE-P capstone. It becomes the spine of my WRITEUP.md once the build is done.

## Primary framework: HIPAA Security Rule

I'm choosing HIPAA Security Rule as my primary framework. Acme Health handles PHI directly through the Patient Intake API, so HIPAA's Technical Safeguards map cleanly onto the encryption, access control, and audit logging work this system needs. I considered SOC 2 and CMMC but rejected both: SOC 2 has no official OSCAL catalog, which adds translation overhead for no real benefit here, and CMMC's federal framing doesn't fit Acme's near-term business, since no federal pilot is part of this scenario beyond a passing mention.

## Gap-to-control-to-layer mapping (finalized)

| Gap | HIPAA control | Terraform | Policy | Monitoring (AWS Config rule) | Notes |
|---|---|---|---|---|---|
| GAP-01: S3 SSE-S3 not KMS | 164.312(a)(2)(iv) + 164.312(a)(1) | Yes, per-bucket CMK from the module | Yes | `s3-default-encryption-kms` | Citing access control (a)(1), not just "encryption exists": SSE-S3 already satisfies (a)(2)(iv) literally, and CMK's real value is key-level access control and audit |
| GAP-02: DynamoDB default key | 164.312(a)(2)(iv) + 164.312(a)(1) | Yes, a dedicated CMK in `kms.tf` and an inline `server_side_encryption` block on the starter's table | Yes | `dynamodb-table-encrypted-kms` | Same reasoning as GAP-01. This key does not come from the S3 module |
| GAP-03: no TLS-deny bucket policy | 164.312(e)(1) | Yes, new bucket policy | Yes | `s3-bucket-ssl-requests-only` | Direct fit: guards against unauthorized access during transmission |
| GAP-04: no S3 versioning | 164.308(a)(7) | Yes, from the module | No dedicated policy | `s3-bucket-versioning-enabled` | Terraform and monitoring only, not one of my 5 flagship policies |
| GAP-05: Lambda not in VPC | 164.312(e)(1) | Yes, `vpc_config` added to the Lambda, plus a private route table, Gateway Endpoints (S3 + DynamoDB), and a security group | Yes | `lambda-inside-vpc` | Same control family as GAP-03, different mechanism: path isolation, not channel encryption. I chose Gateway Endpoints over a NAT Gateway because they're free, keep PHI traffic off the public internet entirely, and have no per-AZ capacity ceiling |
| GAP-06: no concurrency/DLQ/X-Ray | not HIPAA-mapped (SOC 2 CC7.2 / CMMC SI.L2-3.14.6 only) | Partial: X-Ray tracing only | No | No | I'm skipping the DLQ piece deliberately: this Lambda is invoked synchronously via API Gateway, so a DLQ, which is designed for async failures, wouldn't capture anything under normal operation. I'm documenting this as an accepted gap rather than adding a non-functional checkbox. Reserved concurrency is also not possible in this account: the total Lambda concurrency limit is 10, and AWS requires 100 to stay unreserved. API Gateway throttling (GAP-08) is the compensating control |
| GAP-07: IAM `dynamodb:*`/`s3:*` | 164.312(a)(1) | Yes, scoped to specific actions, edited in place | Yes | none | Textbook least privilege. No Config rule can see this gap: the managed IAM rules skip inline policies, and the starter's policy is inline, so the Rego gate is my only detection here |
| GAP-08: no API GW logging/throttling/WAF | 164.312(b), logging only | Logging + throttling yes; WAF likely stays undone | No dedicated policy | `api-gwv2-access-logs-enabled` | Throttling and WAF are availability and attack-surface concerns, not audit trail. Citing 164.312(b) for those would repeat the same over-claim I caught on GAP-01 |

My five flagship HIPAA policies are GAP-01, GAP-02, GAP-03, GAP-05, and GAP-07. These get Terraform, Rego, pipeline enforcement, and OSCAL treatment. GAP-04 gets Terraform, a Config rule, and an OSCAL entry but no Rego policy. GAP-06 and GAP-08 are closed only partially, in Terraform.

## Continuous monitoring and detection, built in from the start

I'm using AWS Config with targeted managed rules instead of custom Lambda detection code, to keep scope small. I checked every rule name and behavior against AWS's documentation, because two of the obvious-looking choices would not have caught their gap: the generic S3 encryption rule passes a bucket that still uses SSE-S3, and the IAM admin-access rule only flags `*` on `*`, and only for customer managed policies.

- `s3-default-encryption-kms` for GAP-01
- `dynamodb-table-encrypted-kms` for GAP-02
- `s3-bucket-ssl-requests-only` for GAP-03
- `s3-bucket-versioning-enabled` for GAP-04
- `lambda-inside-vpc` for GAP-05
- `api-gwv2-access-logs-enabled` for GAP-08

Config also needs a configuration recorder, a delivery channel, and somewhere to write its records. I gave it its own bucket, hardened by the same module as the other buckets, and its own IAM role that can only write under the Config prefix of that bucket and use that bucket's key. The recorder watches only the four resource types the six rules look at (S3 buckets, DynamoDB tables, Lambda functions, and API Gateway stages), which keeps the per-item charge small. The rules are detective controls. They tell me when something drifts, and the Rego policies in Layer 2 are the preventive side.

Config evaluates every S3 bucket in the account, not just the workload's, so it flagged the evidence vault I built in Lab 2.5 as non-compliant on the KMS and TLS rules. That bucket uses SSE-S3 and has no TLS-deny policy, which is what those two rules exist to catch. I'm leaving it alone and treating the finding as proof that the monitoring works on real data.

For alert routing, an EventBridge rule on Config's compliance-change events feeds an SNS topic. This gives real alert routing without building a full notification system. The topic is encrypted with its own KMS key, because the AWS-managed SNS key does not let EventBridge publish to it and alerts would silently never arrive. The email subscription is optional: the `alert_email` variable defaults to an empty string, so anyone can plan and apply the code without giving an address, and the topic and rule still exist. I keep my own address in a gitignored `terraform.tfvars`.

For detection test coverage, `scripts/verify-controls.sh` deliberately reintroduces one gap (for example, removing the versioning setting through the CLI), polls AWS Config for a `NON_COMPLIANT` result, then reverts the change. This proves the control actually fires instead of just assuming it does.

## Terraform structure

```
terraform/
├── main.tf                  # the starter's file, edited in place for GAP-02, 05, 06, 07, 08
├── modules/
│   └── compliant-storage/   # per-bucket CMK + SSE-KMS + versioning + public access block (GAP-01, GAP-04),
│       ├── main.tf          # reused for my own evidence vault bucket
│       ├── variables.tf
│       └── outputs.tf
├── kms.tf                   # dedicated CMK for the DynamoDB table (GAP-02)
├── s3-hardening.tf          # module call for the uploads bucket, TLS-deny bucket policy (GAP-03)
├── network.tf               # private route table, Gateway Endpoints, Lambda security group (GAP-05)
├── api-logging.tf           # access log group for the API (GAP-08)
├── evidence-vault.tf        # Object Lock vault, GOVERNANCE, 30 days, hardened by the module
├── cloudtrail.tf            # multi-region trail with log-file validation, its own key and log bucket (164.312(b))
├── oidc-trust.tf            # planned for Layer 3
└── monitoring.tf            # Config recorder, rules, SNS, EventBridge (164.312(b))
```

The module also hardens the Config bucket, so it is called three times: uploads, evidence, and Config. The CloudTrail log bucket is the one bucket that does not use it. CloudTrail delivers as a service principal, and the module's key policy only trusts my own account, so the trail gets a dedicated key whose policy names CloudTrail and this one trail. The bucket still uses KMS, so the GAP-01 policy holds for every bucket in the account.

Some gaps can be closed with new resources placed next to the starter's, which is the case for GAP-01, 03, and 04. Others live inside a starter resource as an inline block (GAP-02's `server_side_encryption`, GAP-05's `vpc_config`, GAP-06's concurrency and tracing, GAP-08's access logging) or replace an existing policy (GAP-07). Defining the same resource a second time in another file would be an error, and the starter's own comments say the learner is expected to add these in place. So I'm editing `main.tf` directly and marking each change with its GAP comment.

Every new or changed resource gets a control-ID comment directly above it, matching the starter's own `# GAP-02: ...` convention. This gives bidirectional mapping between control and code, not just a table living separately in WRITEUP.md.

The module also declares an explicit public access block on every bucket it hardens. That isn't one of the eight named gaps, because AWS applies a block to new buckets by default, but declaring it in code makes the control visible in the plan and stops it from drifting silently. It supports 164.312(a)(1).

## Policy suite (Layer 2)

Five Rego policies, one per flagship gap, each in its own file and each scoped to a single resource type:

- GAP-01: every S3 bucket encryption configuration must use `aws:kms`
- GAP-02: every DynamoDB table must set `server_side_encryption` with a KMS key
- GAP-03: every S3 bucket holding PHI must have a bucket policy that denies requests where `aws:SecureTransport` is false
- GAP-05: every Lambda function must have a `vpc_config`
- GAP-07: no IAM role policy may allow a service-wide wildcard action such as `s3:*`

Each policy carries a `# METADATA` block naming the framework (`hipaa`), the HIPAA control IDs, a severity, and a remediation. The deny message includes the control ID, so a developer reading a failed PR sees the exact citation. Each policy has its own `_test.rego` with passing and failing fixtures, and the rules are deny-by-default. Conftest runs them against the Terraform plan JSON in the pipeline.

## OSCAL component (Layer 4)

One `component-definition.json` describing what I actually built: implemented-requirements for the gaps I closed (GAP-01 to 05 and 07, and optionally the partial fixes), real Terraform addresses as props, HIPAA 164.x citations as props, and evidence links to a real signed bundle in my vault. A profile selects the controls the component implements. Anything I did not build, such as the DLQ and the WAF, is not claimed in OSCAL and appears only in WRITEUP.md.

I also add cross-references to SOC 2 and CMMC controls in `props` on the relevant implemented-requirements, for example SOC 2 CC7.2 and CMMC SI.L2-3.14.6 for the GAP-06 partial fix. HIPAA remains the only framework in the policies, the profile, and the component's source.

## Decisions and trade-offs

- I'm using us-east-1, matching the starter's default. The scenario states no data-residency requirement.
- The evidence vault uses Object Lock in GOVERNANCE mode. COMPLIANCE is the stronger tamper-resistance claim because nobody, including root, can delete evidence before retention expires, but it also means I cannot clean up a mistake. GOVERNANCE lets a principal with `s3:BypassGovernanceRetention` override the lock, which I accept for a short-lived, single-developer project. For production I would use COMPLIANCE.
- Retention on the vault is 30 days. Reviews take 5 to 7 business days and the reviewer checks that retention is still active, so a short retention such as 1 day would have expired by then. I'll re-run the pipeline shortly before submitting so a fresh bundle exists.
- The pipeline applies automatically on merge to main, after the policy gate passes. This is fully continuous, but it gives the pipeline real deploy power, so I'm limiting the risk with branch protection, a required status check, and an OIDC role scoped to this repository.
- Everything runs in one AWS account, my sandbox. For production the evidence vault would live in a separate account, so a compromise of the audited account could not quietly rewrite the evidence.
- I close each gap in Terraform and use Rego to stop it coming back.
- The capstone overview says the capstone vault is Lab 2.5's vault. I read that as the same design, not the same bucket. The Layer 1 list asks for a KMS-encrypted vault defined in this repo's Terraform, and my Lab 2.5 bucket lives in another repo and uses SSE-S3, so I rebuilt the vault here from the lab's pattern and left the old bucket untouched. It holds the signed bundles from Lab 4.4, so I'm not deleting it before the capstone is reviewed.
- I applied the Layer 1 baseline once by hand from the feature branch, in small chunks, testing each before the next: the workload gaps first, then the vault, then CloudTrail, then monitoring. The brief says not to start the pipeline until the baseline applies clean, and small chunks meant a failure pointed at a few resources instead of forty.
- The write-up will run about five pages, built from this doc, with a control-to-code coverage table and an honest list of what I didn't get to.

## Engineering hygiene decisions

- I added a LICENSE file (MIT), matching what the starter's README already claims but never actually shipped.
- I'm committing `.terraform.lock.hcl` for this project so dependencies stay pinned, since that's explicitly called out in the grading rubric.
- For state management, I'm using local Terraform state deliberately, documenting it as a single-developer, short-timeline trade-off rather than standing up a remote S3 and DynamoDB backend just to satisfy that one rubric line.

## CI/CD pipeline, expanded stages, still one workflow

`lint → validate → security scan (checkov + tfsec) → gitleaks → policy check (Conftest) → apply → sign (Cosign) → upload (vault)`

This is wider than the bare 5 steps described in the brief, matching what the rubric explicitly checks for in CI. It runs on pull requests against main. I'll wire branch protection (require a PR, no bypass, a required status check) once this workflow exists and I have a real job name to point it at.

The repo history will show two pull requests: one green PR that merges, and one red PR that deliberately reintroduces a gap and is blocked by the gate. I'll choose which gap when I build the pipeline.

## Testing strategy

- Rego `_test.rego` fixtures with positive and negative cases, one set per flagship policy.
- `scripts/verify-controls.sh`: integration-level runtime checks against real deployed resources (a non-TLS S3 request that expects `AccessDenied`, confirming the real IAM role has no wildcard actions, confirming the real KMS key is attached to S3 and DynamoDB).
- `scripts/verify-evidence.sh`: chain-of-custody verification on the signed bundle (integrity, authenticity, and retention checks).

## Pre-submission tool pass, run once before shipping

`terraform fmt -check`, `tflint`, `checkov`, `gitleaks`, `semgrep --config=auto`, and `opa test ./policies`, fixing anything HIGH or CRITICAL. I'm treating this as insurance rather than the main scoring lever: end-to-end integration and clear reasoning matter more, but this is cheap to run and catches real problems before submission.

## What I'm deliberately not doing, honest and stated

- GAP-06's DLQ, since synchronous invocation makes it non-functional here.
- GAP-06's reserved concurrency, since this account's Lambda concurrency limit of 10 leaves nothing to reserve (AWS requires 100 to stay unreserved). API Gateway throttling is the compensating control.
- GAP-08's WAF, since the ongoing cost and complexity isn't worth the added scope for this timeline.
- A Config rule for GAP-07, since AWS's managed IAM rules don't evaluate inline policies.
- CloudTrail data events for S3 and DynamoDB. They would record every object and item access, which is closer to what an auditor wants for PHI, but they are billed per event and the trail's management events already cover who changed what.
- Recording every Config resource type. I record only the four the rules use.
- A remote Terraform state backend: a documented choice, not something I built.
- Automated retry and dead-letter handling on the evidence pipeline itself, which I'm noting as a "with another sprint" item.

## Open decisions

- The OSCAL catalog for HIPAA is still open. NIST publishes OSCAL catalogs for SP 800-53 and SP 800-171, but none for HIPAA or SP 800-66 (I checked the usnistgov/oscal-content repository). The starter's FRAMEWORKS.md suggests citing SP 800-66 Rev. 2 as the catalog and putting the 164.x sections in `props`. I haven't decided how the component's `control-implementation.source` and the profile will point at it, and I'll settle that before building this layer.
- The pass threshold is also unsettled. The live rubric gives it as 65 in its header and 80 in its body, and the Capstone Overview PDF (also v1.1.0) says 65. I'm designing to the stricter 80 until that's clear.

## Requirements sources and how I ranked them

The documents I worked from don't always agree with each other, so I ranked them up front.

| Tier | Source | How I use it |
|---|---|---|
| Primary | The live CGE-P capstone rubric on cert.grcengclub.com, and the Lab 7.1 Capstone Companion in the cgep-lab-guide-rework wiki | Wins any conflict |
| Secondary | The Capstone Overview PDF (v1.1.0), the original capstone brief and companion, and the starter's GAPS.md, FRAMEWORKS.md, and WORKLOAD.md | Detail and context, where they agree with the primary sources |
| Reference only | The capstone sections of the CGE-P Study Guide and the IaC Portfolio Assessment in the Exam Blueprint (both version 1.0, older than the Overview) | Hints and sanity checks, never proof. I don't change the design because of them alone |
| Not used as requirements | The 4-category weighting (35/30/20/15) and a separate COMPLIANCE.md file, both from the older exam-side documents | The newer v1.1.0 documents use the 8-dimension rubric instead, and COMPLIANCE.md appears in only one source. The rubric's control-to-code mapping check is covered by the coverage table in my write-up |
