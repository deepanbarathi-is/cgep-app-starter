# Acme Health Patient Intake API: CGE-P capstone

This is my CGE-P capstone: a fork of `GRCEngClub/cgep-app-starter`, the deliberately non-compliant Patient Intake API, governed under the HIPAA Security Rule. The starter's eight named gaps (`GAPS.md`) are closed six ways in full and two partially, with a Terraform baseline, five Rego policies with tests, a GitHub Actions pipeline that plans, gates, applies, signs, and uploads evidence on every change, and an OSCAL component. The full reasoning is in `WRITEUP.md`; the build log and every design decision along the way is in `DESIGN.md`.

## Verify the compliance work

None of these need an AWS account. Run from the repo root.

```bash
opa test ./policies                          # 57 unit tests across the 5 policies
test/policy-breaks.sh                        # the gate blocks 7 real deliberate breaks, one per gap
test/plan-guard-breaks.sh                    # the empty-plan guard rejects a malformed plan
test/verify-evidence-breaks.sh               # the evidence verifier catches 5 kinds of tampering
scripts/verify-evidence.sh --dir evidence-samples/run-36292858361
```

`opa` and `conftest` come from the [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/#running-opa) releases. `scripts/verify-evidence.sh` needs [`cosign`](https://docs.sigstore.dev/system_config/installation/) on the path; the last command checks a real signed evidence bundle committed in `evidence-samples/`, recomputing its SHA-256, verifying the Cosign signature against this exact GitHub Actions workflow, and reporting the Object Lock retention recorded in its receipt. Add `--live` (with AWS credentials for the account this was built in) to re-check that retention directly against the vault instead of trusting the receipt.

The OSCAL files validate with [`trestle`](https://oscal-compass.github.io/compliance-trestle/) (`pip install compliance-trestle`), from the repo root, which already has a `.trestle/config.ini` marker:

```bash
trestle partial-object-validate -tr . -f oscal/catalogs/hipaa-164-subset/catalog.json -e catalog
trestle partial-object-validate -tr . -f oscal/profiles/hipaa-minimum/profile.json -e profile
trestle partial-object-validate -tr . -f oscal/components/acme-health-intake/component-definition.json -e component-definition
```

## Deploy it

The starter's resources are unchanged and still runnable, in whoever's own AWS sandbox account runs this. This deploys into the credentials on your machine, not mine.

```bash
make creds AWS_PROFILE=<your-sandbox-profile>
make deploy AWS_PROFILE=<your-sandbox-profile>
make test   AWS_PROFILE=<your-sandbox-profile>
```

`make test` should return `{"submission_id": "...", "status": "received"}`. The GitHub Actions pipeline (`.github/workflows/grc-gate.yml`) is wired to the AWS account and OIDC trust I built for my own account; running it against a different account needs a matching state bucket, OIDC roles, and evidence vault, which `terraform/state-bucket.tf`, `terraform/oidc-trust.tf`, and `terraform/evidence-vault.tf` show how to build. `make destroy` tears it back down.

## Layout

```
terraform/          the baseline: KMS, VPC hardening, the evidence vault, CloudTrail, Config, the pipeline's OIDC roles
policies/            5 Rego policies and their tests, one per flagship gap
.github/workflows/   grc-gate.yml: plan, gate, apply on merge, sign, upload
oscal/               the HIPAA catalog, profile, and component
scripts/             build/upload/verify the evidence bundle; verify-controls.sh proves detection on a live account
test/                break tests for the policy gate, the empty-plan guard, and the evidence verifier
evidence-samples/    one real signed bundle, its signature, and its receipt, committed for offline verification
GAPS.md, FRAMEWORKS.md, WORKLOAD.md   the starter's own scenario and gap descriptions
DESIGN.md            the design log, written as the project was built
WRITEUP.md           the required write-up
```

## Cost and cleanup

Roughly $0 if destroyed promptly. The six KMS keys are the only thing billed while idle, at about a dollar each per month. `make destroy` removes the deployed workload; the state bucket, the OIDC roles, and the evidence vault are separate Terraform resources in `terraform/` and would need their own destroy pass, in that order, since the state bucket holds the state for everything else.

## License

MIT.
