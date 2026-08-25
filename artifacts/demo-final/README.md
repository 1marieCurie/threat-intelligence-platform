# Final demo evidence

Store only report/video evidence here. Never store `.env`, OAuth credentials, tokens, passwords or raw database dumps.

Recommended screenshot names:

1. `01_dashboard_before.png` — Dashboard before the transition, with confirmed/potential exposure counts.
2. `02_real_cve_confirmed.png` — CVE-2021-44228 on `PFA-DEMO-CONFIRMED`, showing `log4j-core 2.14.1`, confirmed and HIGH.
3. `03_priority_transition_terminal.png` — concise terminal result from `trigger-priority`.
4. `04_gmail_priority_critical.png` — received Gmail subject and message, with no secrets visible.
5. `05_alert_list_sent.png` — Alerts page showing the new event and delivery state.
6. `06_alert_detail_reason.png` — Alert detail explaining why it was triggered.
7. `07_dashboard_after.png` — Dashboard after the CRITICAL transition.
8. `08_kev_transition.png` — optional report evidence for non-KEV -> KEV.
9. `09_potential_no_alert.png` — optional report evidence showing potential exposure and zero generated alert.
10. `10_dedup_replay.png` — terminal proof that replay creates zero duplicate alerts.
11. `11_staff_role.png` — staff navigation limited to Analyse URL + Centre d'aide.
12. `12_public_url_analysis.png` — optional public URL analysis result.

For the final video, only screenshots/clips 01–07 are normally needed. The others are better suited to the written report or appendix.

After capturing images locally, copy them into `artifacts/demo-final/screenshots/` and commit them only on this test/evidence branch if you want the report evidence preserved in Git.
