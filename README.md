# tripwire

Catches stolen AWS keys from CloudTrail. Each identity gets its own Isolation Forest, so "unusual" means unusual for *that* key, not for the account. Flagged calls are grouped into one incident per identity and source IP, tagged with MITRE ATT&CK techniques, and sent to Slack as a single message that updates as the attacker keeps going.

```
CloudTrail ──> EventBridge ──> Lambda ──┬─> DynamoDB  recent calls (10 min window, TTL)
                                        ├─> S3        per identity forests (JSON)
                                        ├─> DynamoDB  baselines + incidents
                                        ├─> Bedrock   2 to 3 sentence summary (optional)
                                        └─> Slack     one message per incident, edited in place
```

## Results

Trained on one week of synthetic traffic (5,000 events, 5 identities). Tested on a **different** week (5,000 new normal events) with a 9 call stolen key attack injected. Thresholds come from training data only: each identity's 99.7th percentile score.

| seed | attack calls caught | false positives | fp rate | incidents raised | attack became |
|---|---|---|---|---|---|
| 1 | 8/9 | 27/5000 | 0.54% | 5 | 1 HIGH incident |
| 2 | 9/9 | 6/5000 | 0.12% | 7 | 1 HIGH incident |
| 3 | 9/9 | 15/5000 | 0.30% | 9 | 1 HIGH incident |
| 4 | 9/9 | 19/5000 | 0.38% | 16 | 1 HIGH incident |
| 5 | 8/9 | 15/5000 | 0.30% | 11 | 1 HIGH incident |

Every attack was caught as exactly one HIGH incident. Per call recall was 8 or 9 of 9, at a 0.33% mean false positive rate. The call that gets missed is usually the first `GetCallerIdentity`: it happens before the burst features have anything to count. Scoring takes about 0.12 ms per event in pure Python.

Reproduce: `python -m scripts.evaluate --seeds 5`. CI runs it on every push.

## The features

All seven are computed against the calling identity's own history:

| feature | what it catches |
|---|---|
| api_rarity | a reporting job calling `CreateAccessKey` |
| ip_rarity | a source IP this key has never used |
| region_rarity | instances launched in a region you don't use |
| ua_rarity | `aws-cli ... kali` instead of the job's usual boto3 |
| hour_rarity | 3am activity from a 9 to 5 identity |
| burst | 9 calls in 6 minutes from a key that makes 4 an hour |
| error_burst | AccessDenied after AccessDenied while the attacker probes permissions |

Training uses leave one out rarity. A one-off IP in the history scores exactly as rare as a brand new IP at runtime, so the forest learns what normal one-offs look like. There's a test for this.

## Design decisions

- **Train with scikit-learn, score without it.** sklearn, numpy and scipy are too heavy for a Lambda package. `model.py` exports each tree's arrays to JSON and walks them in plain Python. `test_exported_forest_matches_sklearn` checks the result equals `score_samples` to 1e-12.
- **Per identity thresholds.** One global cutoff lets a noisy identity drown out a quiet one. Each forest keeps its own 99.7th percentile.
- **Live traffic never updates the baselines.** Retraining is a separate step (`scripts/train.py`). Otherwise an attacker who goes undetected long enough teaches the model that their behaviour is normal.
- **One incident, one message.** Incidents are keyed by `identity#source_ip` and split after 30 quiet minutes. The first flagged call posts to Slack and later ones `chat.update` the same message.
- **The LLM is optional.** Bedrock only gets the extracted facts and only writes the summary. If it fails, the alert still goes out with the raw facts.
- **The Lambda never scores itself.** The EventBridge rule excludes the detector's own role, so its own DynamoDB and S3 calls don't feed back into it.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q                                   # 10 tests, fakes for DynamoDB/S3/Slack
python -m scripts.evaluate --seeds 5        # the table above
```

Deploy to a sandbox account:

```bash
cd infra && terraform init && terraform apply
python -m scripts.train --logs ./cloudtrail-logs \
  --bucket "$(terraform -chdir=infra output -raw model_bucket)" \
  --table  "$(terraform -chdir=infra output -raw baseline_table)"
```

Optional: put a Slack bot token in the created secret, then `terraform apply -var enable_slack=true -var bedrock_model_id=<model id>`.

`.github/workflows/redteam.yml` is a manual workflow. It runs four Stratus Red Team techniques (discovery, secrets retrieval, admin user creation, CloudTrail stop) against the deployed stack and fails if no HIGH incident appears within 10 minutes.

## Dashboard

`web/` is a Next.js dashboard over one replayed week: incidents, the decoded features behind every flagged call, each identity's scores against its threshold, and the evaluation table. It reads a snapshot from the real pipeline, not mock data:

```bash
python -m scripts.export_web --seed 3
cd web && npm install && npm run dev
```

## Limits

- The numbers above come from synthetic traffic. Real accounts are noisier. The next step is replaying a public CloudTrail dataset and reporting those numbers separately.
- CloudTrail events reach EventBridge in the region where the call was made, and IAM and STS events land in us-east-1. Multi-region coverage means deploying the rule in each region you use.
- Check in your account that read-only events (`List*`, `Describe*`, `Get*`) actually reach EventBridge. Most attacker recon is read-only.
- An attacker who copies the victim's user agent and works from inside its usual IP range will look a lot more normal. Tripwire is one layer, not the whole defence.

## Layout

```
tripwire/events.py      CloudTrail record -> Event
tripwire/features.py    7 rarity features, leave one out, 10 minute windows
tripwire/model.py       sklearn training, JSON export, pure Python scoring
tripwire/incidents.py   grouping, MITRE mapping, severity, Slack text
tripwire/handler.py     Lambda entry point
tripwire/simulate.py    synthetic traffic and the attack
scripts/                evaluate, train, check_incident, export_web
web/                    Next.js dashboard
infra/                  Terraform for everything
```
