# FraudGuard WAFGuard

Turn AWS WAF detections into temporary IP protection across your applications. WAFGuard reads your WAF logs, checks your FraudGuard customer lists, and can add qualifying IPs to your FraudGuard blacklist. Optional synchronization applies your effective blacklist to dedicated AWS WAF IPv4 and IPv6 IP sets.

WAFGuard runs in **your AWS account**, using your FraudGuard credentials. It is included with **Professional, Business, and Enterprise**; AWS resources and usage are billed separately.

**[Download wafguard.yml](https://raw.githubusercontent.com/fraudguard-io/scripts/main/wafguard-cloudformation/wafguard.yml)** — the template contains the Python processor. No local build, Python installation, or separate code upload is needed.

[Install](#install-in-observation-mode) · [Enable protection](#enable-protection) · [Configuration](#configuration-reference) · [Troubleshooting](#verify-and-troubleshoot) · [Customization](#customization-and-license)

## How it works

1. EventBridge runs the Lambda processor every minute to read recent WAF log files from S3.
2. Requests matching your selected WAF rule IDs or labels become evidence. By default, an IP needs **three distinct matching requests within five minutes**, plus an ACE v2 recommendation to block.
3. With publishing enabled, qualifying IPs receive a temporary FraudGuard blacklist entry tagged `source:wafguard`. Active customer whitelist entries take precedence; already-blacklisted IPs are skipped before writing.
4. With synchronization enabled, WAFGuard mirrors the **entire effective FraudGuard blacklist**, including entries added by other integrations, excluding expired and whitelisted IPs.

Start in **Observe** mode: it performs reads and records findings in DynamoDB and CloudWatch, but does not publish blacklist entries, update IP sets, or send notifications. It still uses FraudGuard API allowance.

This protects against **subsequent activity**. AWS WAF [delivers S3 logs approximately every five minutes](https://docs.aws.amazon.com/waf/latest/developerguide/logging-s3.html); WAFGuard processes available files on a scheduled invocation. It does not replace your existing WAF rules or block the first request in real time.

## Requirements

- A FraudGuard **Professional or higher** account and its API username/password.
- An existing **regional AWS WAF web ACL** with native WAF logging enabled to an S3 bucket named `aws-waf-logs-...`. Deploy one stack per web ACL in the same AWS account and region. CloudFront web ACLs are not supported.
- Logging filters that retain your selected rule/label evidence. Retain Count matches too if you select them; they can have a final `ALLOW` action.
- An existing Secrets Manager secret in that account and region containing the following JSON, with your actual API credentials:

  ```json
  {"username": "YOUR_FRAUDGUARD_API_USERNAME", "password": "YOUR_FRAUDGUARD_API_PASSWORD"}
  ```

- Permission to create Lambda, IAM, DynamoDB, CloudWatch Logs, and EventBridge resources. Optional features add WAF IP sets/rule group and SNS resources. Restrictive bucket or KMS key policies must also permit the Lambda role's access.

Use the secret's **ARN** when deploying. Do not put credentials into the template or GitHub.

## Install in observation mode

1. Download **[wafguard.yml](https://raw.githubusercontent.com/fraudguard-io/scripts/main/wafguard-cloudformation/wafguard.yml)**. In CloudFormation, choose **Create stack → With new resources → Upload a template file**, in the web ACL's region. Do not use the resource-import workflow.
2. Name the stack and enter these inputs. Other settings can keep their defaults for the first run.

   | Parameter | What to enter |
   | --- | --- |
   | `WafLogBucket` — required | Existing log bucket **name only**, such as `aws-waf-logs-myapp`. |
   | `WebAclArn` — required | Web ACL ARN containing `regional/webacl/`. |
   | `FraudGuardSecretArn` — required | ARN of the secret containing the JSON above. |
   | `FraudGuardPlan` | Your actual subscription: `Professional` (default), `Business`, or `Enterprise`. |
   | `SelectedRuleIds` and/or `SelectedLabels` — at least one required | Security identifiers from your WAF logs; both default blank. See below. |
   | `WafLogPrefix` — conditional | Leave blank for `AWSLogs/...`. For `security/AWSLogs/...`, enter only `security/`. |
   | `KmsKeyArn` — conditional | Required if a customer-managed KMS key encrypts the secret or log objects; otherwise blank. |

3. Keep `DetectionPolicy=WafAndAce`, `Mode=Observe`, `PublishBlacklist=false`, `SyncWaf=false`, and `NotificationMode=None`. Acknowledge IAM resource creation and create the stack.
4. After `CREATE_COMPLETE`, open the log group named by the **`CloudWatchLogGroup` output**. Generate controlled traffic matching your selected rules, allow for S3 delivery, and review decisions. Confirm legitimate traffic is not qualifying before enabling protection.

### Choose evidence and detection policy

Use rule IDs from actual [WAF log records](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html), including inner managed-rule IDs. For example, `SQLi_QUERYARGUMENTS,CrossSiteScripting_QUERYARGUMENTS` selects those exact IDs **if your enabled rules emit them**. You do not need to select every rule.

Selectors are comma-separated and case-sensitive. Rule IDs match exactly; labels match exactly or by a nonempty prefix ending in `*`. A request matching either selector counts once. A final Block, Count, CAPTCHA, or Challenge action alone is not sufficient evidence. Endpoint probing without selected security matches remains observational.

| Policy | What qualifies an IP |
| --- | --- |
| `WafAndAce` — default | Selected WAF evidence reaches your defined threshold **and** a fresh ACE verdict recommends blocking. |
| `WafOnly` | Selected WAF evidence reaches the same threshold, without ACE enrichment. Set `BlacklistTtlSecondsOverride` to at least `60`; for example, `900` for 15 minutes. |

**Both policies still check the customer's FraudGuard whitelist and blacklist.** WafOnly skips ACE and its cache, not customer-list checks or credentials. Choose accurate selectors: it has no independent ACE verdict to corroborate them.

WAFGuard uses WAF's `httpRequest.clientIp`. Verify attribution if another proxy sits in front of WAF; it does not substitute a caller-supplied forwarding header.

## Enable protection

Update the existing CloudFormation stack, keeping its template and existing input values. For the complete workflow, set:

| Setting | Value | Effect |
| --- | --- | --- |
| `Mode` | `Enforce` | Enables the actions selected below. |
| `PublishBlacklist` | `true` | Allows new qualifying entries in FraudGuard. |
| `SyncWaf` | `true` | Creates dedicated IP sets and a rule group, and synchronizes them. |

**FraudGuard additions can affect every integration using that account's blacklist**, not only this web ACL. Synchronization includes existing entries created elsewhere; it is not limited to WAFGuard-tagged entries.

After the update completes:

1. Copy **`WafGuardRuleGroupArn`** from the stack outputs.
2. Add that rule group to your existing web ACL through the WAF console or your infrastructure code. Use **override action None** and a priority where earlier Allow rules will not bypass your intended protection. WAFGuard does not attach the group or rewrite your web ACL.
3. Send fresh controlled traffic and verify the FraudGuard addition, AWS IP-set membership, and actual blocking. Completed observation batches are not automatically replayed when publishing is enabled.

Under the default WafAndAce policy, even selected WAF matches will not blacklist an IP unless ACE recommends blocking it. For an isolated test of publication without reputation, use WafOnly with an explicit duration and a non-whitelisted test IP. A whitelisted test IP should be skipped under either policy.

The controls are independent: `Enforce` + `SyncWaf=true` + `PublishBlacklist=false` synchronizes and expires **existing** entries without creating new ones. Enforce alone enables neither action. Observe mode stops runtime writes regardless of the switches.

## Blacklist duration and automatic cleanup

**Temporary bans are cleaned up in both FraudGuard and AWS WAF.** FraudGuard stops applying an entry when its TTL expires. With `Mode=Enforce` and `SyncWaf=true`, WAFGuard removes it from its IP sets on the next successful synchronization, followed by AWS propagation. No new traffic is needed.

Under WafAndAce, `BlacklistTtlSecondsOverride=0` uses the ACE recommendation's **remaining validity**. A fresh `recommendation.cache_ttl_seconds: 28800` means eight hours; if that recommendation is two hours old, the requested ban is six hours. A positive override, such as `3600`, requests a one-hour ban instead. FraudGuard's returned expiry is authoritative.

`CacheTtlSecondsOverride` is separate: `0` follows ACE cache guidance. Extending the cache does not extend the original ACE-derived ban duration. Explicit ban durations still require a valid ACE verdict under WafAndAce. WafOnly requires a positive ban duration and ignores ACE cache settings.

Cached lookups and synchronization do not restart expiry. Fresh qualifying evidence is required for a new ban; WAFGuard's own blocking rules do not count toward renewal.

**Keep the worker running for AWS cleanup.** AWS IP sets have no native per-IP TTL. Observe mode, a stopped worker, or failed AWS updates can leave old addresses in the sets. 

## Optional notifications

| `NotificationMode` | Setup |
| --- | --- |
| `None` — default | CloudWatch logs only. |
| `CreateTopic` | Creates an SNS topic. Optionally enter `NotificationEmail`, or add subscriptions using the `CreatedNotificationTopicArn` output. |
| `ExistingTopic` | Supply `ExistingSnsTopicArn` for a standard SNS topic in this account and region. Manage its subscriptions yourself. |

**Email requires confirmation after deployment.** Open the Amazon SNS email and select **Confirm subscription**. Check **Spam/Junk** for both confirmation and later alerts. Stack creation does not confirm the subscription for you.

SNS can send the same event to **email, SMS, SQS, Lambda, and compatible HTTPS endpoints**. For PagerDuty, subscribe a Lambda adapter that maps the event to [PagerDuty Events API v2](https://support.pagerduty.com/main/docs/services-and-integrations#create-a-generic-events-api-integration). Adapters can also route events to Slack or Microsoft Teams. Customers configure these subscriptions/adapters; the template only offers an optional email subscription. See [SNS destinations](https://docs.aws.amazon.com/sns/latest/dg/sns-event-destinations.html).

Notifications report **confirmed new WAFGuard blacklist additions** in Enforce mode, with the IP, reason, expiry, and event ID. Consumers should deduplicate by event ID. There are no expiry/resolution notifications or automatic PagerDuty incident resolution. A notification confirms the FraudGuard addition, not downstream WAF enforcement.

## Configuration reference

Required installation inputs appear above. Settings below are optional unless stated otherwise. Change them through **CloudFormation**, so permissions, rule actions, and Lambda configuration stay consistent.

| Parameter | Default | Purpose / requirement |
| --- | --- | --- |
| `DetectionPolicy` | `WafAndAce` | ACE-assisted detection or `WafOnly`. |
| `Mode` | `Observe` | Observe decisions or enforce enabled actions. |
| `PublishBlacklist` | `false` | Enable new FraudGuard additions in Enforce mode. |
| `SyncWaf` | `false` | Create dedicated WAF resources; synchronize in Enforce mode. Requires rule-group attachment. |
| `MinimumSecurityMatches` | `3` | Distinct selected requests per IP within the evidence window; 1–1,000. |
| `BlacklistTtlSecondsOverride` | `0` | Remaining ACE validity, or 60–31,536,000 seconds. **Positive duration required for WafOnly.** |
| `NotificationMode` | `None` | `None`, `CreateTopic`, or `ExistingTopic`. |
| `ExistingSnsTopicArn` | Blank | **Required for ExistingTopic**; standard topic in this account/region. |
| `NotificationEmail` | Blank | Optional email subscriber; **CreateTopic only**. |

<details>
<summary>Advanced settings and processing limits</summary>

| Parameter | Default | Purpose |
| --- | --- | --- |
| `EvidenceWindowSeconds` | `300` | Group requests by timestamp, in seconds; 60–3,600. Not an added processing delay. |
| `MaxEventAgeSeconds` | `900` | Maximum request age including delivery delay; 300–3,600 seconds. Older events are skipped. |
| `CacheTtlSecondsOverride` | `0` | Follow ACE guidance, or override cache duration up to 31,536,000 seconds. Ignored by WafOnly. |
| `DailyLookupBudget` | `10000` | Attempted ACE IP lookups per UTC day for this stack. Each bulk IP counts; retries can consume more. Excludes list reads/writes; ignored by WafOnly. |
| `MaxObjectBytes` | `33554432` | Compressed/decompressed file size limit: 32 MiB by default, up to 128 MiB. Oversized files are rejected or processing stops at the limit. |
| `MaxObjectsPerRun` | `100` | Files attempted per invocation; up to 1,000. Remaining files can age out if processing falls behind. |
| `CloudWatchLogRetentionDays` | `14` | Retention for Lambda logs only. |

`KmsKeyArn` supports one customer-managed key for the logs/secret, whose policy must permit the Lambda role. Multiple keys or a customer-managed encrypted SNS topic require corresponding IAM/KMS extensions to the template.

Ingestion scans a bounded recent window, not a historical or lossless archive. Monitor `ingestion_limit`, `object_rejected`, and deferred work to ensure processing keeps up. Each AWS IP set holds at most 10,000 addresses. Above capacity, WAFGuard prunes expired/ineligible existing addresses and defers additions for that family, logging `waf_sync_capacity_exceeded`.

</details>


## Troubleshoot


In CloudWatch Logs Insights, select the output log group and run:

```text
fields @timestamp, event, ip, mode, detection_policy, status, reason,
       publish_blacklist, sync_waf, http_status, entries
| filter component = "wafguard"
| sort @timestamp desc
| limit 100
```

## Data, updates, and removal

Raw logs remain in your S3 bucket. Your DynamoDB table stores selected evidence, deduplication records, decisions, ACE cache, customer-list snapshots, and processing/notification state; CloudWatch stores operational findings. Selected IPs go to FraudGuard for enrichment under WafAndAce; published IPs go to its blacklist API. Enabled SNS destinations receive notification details. Apply your normal AWS access and retention controls.

## Customization and license

Every FraudGuard customer is welcome to adapt the CloudFormation template and Python code under the [MIT License](LICENSE). Keep the copyright and license notices. The software is provided **as is, without warranty**; results vary by environment. Test and maintain customizations, starting in Observe mode. API access remains subject to your plan and limits.

