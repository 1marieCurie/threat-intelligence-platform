# Final PFA demo — targeted validation plan

This folder exists only on the test branch `test/final-demo-scenarios`.
It does not replace the normal application pipeline and must not be merged into production unless explicitly desired.

## Goal

Produce a short, credible and reproducible final demonstration (about 60–100 seconds) and a small set of screenshots for the final report.

The demo uses the platform's real database models, real `AlertEvaluationPolicyV1`, real `AlertEvaluationService`, real persistence and, when enabled, the real Gmail adapter.

The default CVE is **CVE-2021-44228 (Log4Shell)** and the demo component is `log4j-core 2.14.1`. This is a real vulnerability/component/version combination. The state transitions are controlled replays so the demo does not depend on an external feed changing during recording.

## Important framing for the report

Say **"controlled replay of a threat-intelligence update"**, not "CISA changed the CVE during the recording".

The replay exercises the same V1 alert rules used by the platform:

1. new confirmed CRITICAL exposure;
2. confirmed exposure entering CISA KEV;
3. confirmed exposure moving LOW/MEDIUM/HIGH -> CRITICAL;
4. potential exposure -> no critical V1 alert;
5. same alert replayed -> deduplicated, no duplicate notification.

## One-time preparation

Use a dedicated organization for the demo when possible. Register it from the UI with a real email address that you can open during recording.

Recommended values:

```env
TIP_DEMO_ORGANIZATION_SLUG=pfa-demo
TIP_DEMO_CVE_ID=CVE-2021-44228
```

For real email delivery:

```env
TIP_NOTIFICATION_BACKEND=gmail
TIP_GMAIL_CLIENT_ID=...
TIP_GMAIL_CLIENT_SECRET=...
TIP_GMAIL_REFRESH_TOKEN=...
TIP_GMAIL_SENDER_EMAIL=your-demo-mail@gmail.com
TIP_GMAIL_SENDER_NAME=Threat Intelligence Platform
```

`MIGRATION_DATABASE_URL` must also be configured because the demo runner creates isolated test assets using the owner role.

The target organization must contain at least one active `security_responsible`. For a clean video, use only one active responsible and use an email inbox you can show.

## Commands

From the repository root:

```powershell
python scripts/demo/final_demo_scenarios.py prepare
python scripts/demo/final_demo_scenarios.py status
```

This creates only isolated assets whose hostnames start with `PFA-DEMO-`:

- `PFA-DEMO-CONFIRMED`: `log4j-core 2.14.1`, confirmed, priority HIGH, non-KEV;
- `PFA-DEMO-POTENTIAL`: same product with missing version information, potential, priority HIGH, non-KEV.

### Scenario A — best scenario for the video

```powershell
python scripts/demo/final_demo_scenarios.py trigger-priority
```

Expected result:

- confirmed exposure goes HIGH -> CRITICAL;
- one `priority_transition_to_critical` alert per active security responsible;
- with Gmail configured: alert becomes `sent` and the email subject is `[Threat Intelligence] Priorité passée à CRITICAL`;
- the Alert page and Dashboard reflect the new state.

### Scenario B — KEV transition

Start from a clean preparation:

```powershell
python scripts/demo/final_demo_scenarios.py reset
python scripts/demo/final_demo_scenarios.py prepare
python scripts/demo/final_demo_scenarios.py trigger-kev
```

Expected result: one `confirmed_exposure_entered_kev` alert per active security responsible and a Gmail notification.

### Scenario C — new confirmed critical exposure

```powershell
python scripts/demo/final_demo_scenarios.py trigger-new-critical
```

Expected result: a third demo machine is created with a new confirmed CRITICAL exposure and the `new_confirmed_critical_exposure` rule fires.

### Scenario D — potential must not alert

Start from a clean preparation if necessary:

```powershell
python scripts/demo/final_demo_scenarios.py potential-no-alert
```

Expected result:

- potential exposure can move to CRITICAL;
- `candidate_events=0`;
- `created_alerts=0`;
- no email is sent.

This is a useful report proof that the platform avoids over-alerting uncertain matches.

### Scenario E — deduplication

After Scenario A:

```powershell
python scripts/demo/final_demo_scenarios.py replay-priority
```

Expected result:

- the policy can recognize the same replayed event;
- PostgreSQL deduplication prevents a second alert record;
- `created_alerts=0` and no duplicate email is sent.

### Cleanup

```powershell
python scripts/demo/final_demo_scenarios.py reset
```

This deletes only machines/components/exposures/alerts created by this demo runner. It does not delete the organization, users or canonical CVE data.

## 60–100 second video storyboard

Keep the recording focused. Do not show every test in the video; keep the remaining scenarios for screenshots/report evidence.

**0–10 s — Dashboard before transition**  
Show the demo organization and the confirmed/potential counts.

**10–25 s — Real vulnerability**  
Open `PFA-DEMO-CONFIRMED` or the vulnerability list and show `CVE-2021-44228`, `log4j-core 2.14.1`, applicability `confirmed`, priority `HIGH`.

**25–40 s — Trigger the update**  
In a prepared terminal run:

```powershell
python scripts/demo/final_demo_scenarios.py trigger-priority
```

Keep only the concise result visible: scenario, alert type, sent notification count.

**40–55 s — Gmail proof**  
Open the received email and show the subject `Priorité passée à CRITICAL`. Avoid exposing OAuth credentials or `.env`.

**55–75 s — Platform alert**  
Refresh Alerts, open the new alert and show why it was triggered, the CVE/machine context and delivery status `sent`.

**75–90 s — Dashboard after transition**  
Show CRITICAL/alert indicators updated.

Optional final 10 seconds: public URL analysis. Only include it if the final montage remains below two minutes.

## Report test matrix

| ID | Scenario | Expected evidence | Video? |
| --- | --- | --- | --- |
| T1 | Real CVE confirmed on exact version | CVE detail + machine/component | Yes |
| T2 | HIGH -> CRITICAL | alert + Gmail `sent` | Yes, primary |
| T3 | non-KEV -> KEV | KEV alert + Gmail | Report screenshot |
| T4 | new confirmed CRITICAL | new-critical alert | Report screenshot |
| T5 | potential -> CRITICAL | no alert | Report screenshot |
| T6 | duplicate replay | no duplicate alert/email | Terminal screenshot |
| T7 | Gmail disabled/failure | persisted alert marked failed | Optional technical appendix |
| T8 | public URL benign/malicious | verdict + confidence from model | Optional video/report |
| T9 | role separation | staff sees URL + help only | Report screenshot |

## What not to show

- `.env` or OAuth secrets;
- refresh tokens/client secrets;
- database passwords;
- long terminal logs;
- every navigation page in the video;
- synthetic claims such as "live CISA change" when using a controlled replay.

## Official context for the chosen CVE

Apache documents CVE-2021-44228 as affecting `log4j-core`, including version 2.14.1, with CVSS 10.0. CISA has also documented Log4Shell as an exploited vulnerability. These references can be cited in the written report alongside the platform screenshots.
